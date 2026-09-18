"""Verify that every `ida_*` symbol a source file touches exists in IDA.

The IDAPython stubs shipped with IDA (`<ida>/python/ida_*.py`) are the ground
truth for what the API actually exposes. They cannot be imported outside
IDA (they load native `_ida_*` extensions), so this parses them with `ast` and
builds a module -> exported-name table, resolving `from ida_x import *`
re-exports transitively (that is how `idaapi` gets its surface).

Then every `mod.attr` access and `from mod import name` in the checked sources
is looked up in that table. An unknown name is almost always an API that was
removed or renamed (`get_inf_structure`, `ida_struct`, `ida_enum`,
`find_binary`, ...), i.e. exactly the class of bug that only shows up when the
plugin is loaded into IDA.

The stub tree checked against is the **newest IDA installed**, because that is
what the plugin is actually loaded into. Symbols do not only disappear between
versions -- behaviour changes too (the 9.4 Functions window stopped handing a
usable chooser to action contexts) -- and this tool proves existence only.

Usage:
    python tools/ida_api_lint.py <file-or-dir> [...]
    IDA_PYTHON_DIR=... python tools/ida_api_lint.py .   # pin one tree
"""

import ast
import os
import re
import sys


# Where IDA installs, newest-first within each root. Order inside a directory
# is resolved by version number, not by listing order.
IDA_INSTALL_ROOTS = [
    r"C:\Program Files",
    r"C:\Program Files (x86)",
]
_IDA_DIR_RE = re.compile(r"^IDA (?:Professional|Pro|Free) (\d+)\.(\d+)$")

# Modules whose surface we check. Anything else (os, re, csv, project packages)
# is ignored -- normal tooling already covers those.
CHECKED_PREFIXES = ("ida_", "idaapi", "idautils", "idc")


def find_ida_python_dirs():
    """Every installed IDA stub tree, newest first."""
    found = []
    for root in IDA_INSTALL_ROOTS:
        try:
            entries = os.listdir(root)
        except OSError:
            continue
        for name in entries:
            match = _IDA_DIR_RE.match(name)
            if not match:
                continue
            python_dir = os.path.join(root, name, "python")
            if os.path.isdir(python_dir):
                found.append(((int(match.group(1)), int(match.group(2))),
                              python_dir))
    found.sort(key=lambda item: item[0], reverse=True)
    return [path for _version, path in found]


def find_ida_python_dir():
    env = os.environ.get("IDA_PYTHON_DIR")
    if env:
        return env
    dirs = find_ida_python_dirs()
    return dirs[0] if dirs else None


def _module_exports(path):
    """Top-level names bound by a stub module, plus its `import *` sources."""
    names = set()
    star_from = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            tree = ast.parse(handle.read(), filename=path)
    except SyntaxError:
        return names, star_from

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                names.add(node.target.id)
        elif isinstance(node, ast.ImportFrom):
            if any(alias.name == "*" for alias in node.names):
                if node.module:
                    star_from.append(node.module)
            else:
                for alias in node.names:
                    names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add((alias.asname or alias.name).split(".")[0])
    return names, star_from


class IdaSurface:
    """Lazily-parsed `module name -> exported names` view of the IDA stubs."""

    def __init__(self, python_dir):
        self.python_dir = python_dir
        self._cache = {}

    def exports(self, module, _seen=None):
        if module in self._cache:
            return self._cache[module]

        path = os.path.join(self.python_dir, module + ".py")
        if not os.path.isfile(path):
            self._cache[module] = None
            return None

        seen = _seen if _seen is not None else set()
        if module in seen:
            return set()
        seen.add(module)

        names, star_from = _module_exports(path)
        for other in star_from:
            inherited = self.exports(other, seen)
            if inherited:
                names |= inherited

        # SWIG stubs also expose whatever the native module carries; names that
        # start with `_` are private plumbing we never reference anyway.
        self._cache[module] = names
        return names


def _checked(module):
    return module.startswith(CHECKED_PREFIXES)


def check_file(path, surface):
    """Return a list of (line, module, name) references not found in IDA 9.0."""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        source = handle.read()
    tree = ast.parse(source, filename=path)

    directory = os.path.dirname(os.path.abspath(path))

    def is_local(module):
        """A sibling module shadows the IDA namespace (e.g. tools/ida_api_lint)."""
        head = module.split(".")[0]
        return (os.path.isfile(os.path.join(directory, head + ".py"))
                or os.path.isdir(os.path.join(directory, head)))

    aliases = {}   # local name -> real module name
    problems = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if not _checked(alias.name):
                    continue
                if is_local(alias.name):
                    continue
                aliases[alias.asname or alias.name] = alias.name
                if surface.exports(alias.name) is None:
                    problems.append((node.lineno, alias.name, "<module missing>"))
        elif isinstance(node, ast.ImportFrom):
            if not node.module or not _checked(node.module):
                continue
            if is_local(node.module):
                continue
            exports = surface.exports(node.module)
            if exports is None:
                problems.append((node.lineno, node.module, "<module missing>"))
                continue
            for alias in node.names:
                if alias.name != "*" and alias.name not in exports:
                    problems.append((node.lineno, node.module, alias.name))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        if not isinstance(node.value, ast.Name):
            continue
        module = aliases.get(node.value.id)
        if module is None:
            continue
        exports = surface.exports(module)
        if exports is None:
            continue  # already reported once at its import site
        if node.attr not in exports:
            problems.append((node.lineno, module, node.attr))

    return problems


def iter_sources(targets):
    for target in targets:
        if os.path.isfile(target):
            yield target
        for root, dirs, files in os.walk(target):
            dirs[:] = [
                d for d in dirs
                if d not in (".git", "__pycache__", ".venv", "reference", "ida-pro-mcp")
            ]
            for name in sorted(files):
                if name.endswith(".py"):
                    yield os.path.join(root, name)


def _version_label(python_dir):
    """"IDA 9.4" for a stub path, so a failure names the version it checked."""
    name = os.path.basename(os.path.dirname(os.path.abspath(python_dir)))
    match = _IDA_DIR_RE.match(name)
    return "IDA %s.%s" % match.groups() if match else name


def main(argv):
    targets = argv[1:] or ["."]
    python_dir = find_ida_python_dir()
    if not python_dir:
        print("ida_api_lint: IDA python dir not found; set IDA_PYTHON_DIR")
        return 2

    surface = IdaSurface(python_dir)
    total = 0
    for path in iter_sources(targets):
        try:
            problems = check_file(path, surface)
        except SyntaxError as exc:
            print("%s: SYNTAX ERROR: %s" % (path, exc))
            total += 1
            continue
        for lineno, module, name in problems:
            print("%s:%d: %s.%s not in %s"
                  % (path, lineno, module, name, _version_label(python_dir)))
            total += 1

    print("ida_api_lint: %d problem(s) [stubs: %s]" % (total, python_dir))
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
