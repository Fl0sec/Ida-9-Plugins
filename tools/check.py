"""Offline sanity gate for IDA plugins -- run this before every commit.

IDA plugins cannot be unit-tested outside IDA, but three whole classes of bug
*can* be caught without launching it:

  1. compile   -- syntax errors in every .py file.
  2. api       -- `ida_*` symbols that do not exist in the IDA the plugin will
                  be loaded into: the newest installed, or IDA_PYTHON_DIR
                  (tools/ida_api_lint.py).
  3. import    -- cross-module wiring (bad `from .x import y`, typos in shared
                  helpers, import-time crashes) by importing each module with
                  the IDA modules replaced by permissive stubs.

Pass 3 is the reason plugin entry files must keep import-time work trivial: if
importing a module needs a live IDB, it cannot be checked here.

Usage:
    python tools/check.py                 # the whole repo
    python tools/check.py cfs5-transfer   # one plugin
    python tools/check.py --no-import cfs5-transfer
"""

import argparse
import importlib
import os
import py_compile
import sys
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ida_api_lint  # noqa: E402


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {".git", "__pycache__", ".venv", "reference", "ida-pro-mcp"}

# Every module name an IDA plugin may import that only exists inside IDA.
IDA_MODULE_PREFIXES = ("ida_", "idaapi", "idautils", "idc", "idahelper")


class _StubMeta(type):
    """Metaclass making stub classes usable as constants, flags and bases."""

    def _combine(cls, _other):
        return cls

    __or__ = __ror__ = __and__ = __rand__ = _combine
    __xor__ = __rxor__ = __add__ = __radd__ = __sub__ = _combine
    __lshift__ = __rshift__ = __invert__ = _combine

    def __int__(cls):
        return 0

    def __index__(cls):
        return 0

    def __bool__(cls):
        return True

    def __iter__(cls):
        return iter(())

    def __call__(cls, *args, **kwargs):
        return _StubInstance()


class _StubInstance(object):
    """Permissive stand-in for any IDA object returned at import time."""

    def __getattr__(self, name):
        return _StubInstance()

    def __call__(self, *args, **kwargs):
        return _StubInstance()

    def __iter__(self):
        return iter(())

    def __int__(self):
        return 0

    def __index__(self):
        return 0

    def __bool__(self):
        return True


class _StubModule(types.ModuleType):
    def __getattr__(self, name):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        stub = _StubMeta(name, (object,), {})
        setattr(self, name, stub)
        return stub


class _StubFinder(object):
    """Import hook that fabricates any `ida_*` module on demand."""

    def find_module(self, fullname, path=None):
        return self if fullname.startswith(IDA_MODULE_PREFIXES) else None

    def load_module(self, fullname):
        module = sys.modules.get(fullname)
        if module is None:
            module = _StubModule(fullname)
            module.__loader__ = self
            sys.modules[fullname] = module
        return module

    # PEP 451 surface, used by modern importlib.
    def find_spec(self, fullname, path=None, target=None):
        if not fullname.startswith(IDA_MODULE_PREFIXES):
            return None
        return importlib.machinery.ModuleSpec(fullname, _StubLoader())


class _StubLoader(object):
    def create_module(self, spec):
        return _StubModule(spec.name)

    def exec_module(self, module):
        return None


def iter_sources(targets):
    for target in targets:
        if os.path.isfile(target):
            yield os.path.abspath(target)
            continue
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in sorted(files):
                if name.endswith(".py"):
                    yield os.path.abspath(os.path.join(root, name))


def pass_compile(sources):
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        cfile = os.path.join(tmp, "out.pyc")
        for path in sources:
            try:
                py_compile.compile(path, cfile=cfile, doraise=True)
            except py_compile.PyCompileError as exc:
                print("COMPILE %s" % exc)
                failures += 1
    print("check: compile -- %d file(s), %d failure(s)" % (len(sources), failures))
    return failures


def pass_api(targets):
    python_dir = ida_api_lint.find_ida_python_dir()
    if not python_dir:
        print("check: api -- SKIPPED (IDA python dir not found; set IDA_PYTHON_DIR)")
        return 0
    return ida_api_lint.main(["ida_api_lint"] + list(targets)) and 1 or 0


def pass_import(sources):
    """Import each module with IDA stubbed; report import-time breakage."""
    sys.meta_path.insert(0, _StubFinder())
    failures = 0
    checked = 0

    for path in sources:
        directory = os.path.dirname(path)
        name = os.path.splitext(os.path.basename(path))[0]
        if name == "__init__":
            continue
        # A file inside a package is reached through its package, not directly.
        if os.path.isfile(os.path.join(directory, "__init__.py")):
            continue
        if directory not in sys.path:
            sys.path.insert(0, directory)
        try:
            spec = importlib.util.spec_from_file_location("_check_%s" % name, path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            checked += 1
        except Exception as exc:
            print("IMPORT %s: %s: %s" % (path, type(exc).__name__, exc))
            failures += 1

    print("check: import -- %d module(s), %d failure(s)" % (checked, failures))
    return failures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", nargs="*", default=None,
                        help="files or directories (default: repo root)")
    parser.add_argument("--no-api", action="store_true")
    parser.add_argument("--no-import", action="store_true")
    args = parser.parse_args(argv)

    targets = args.targets or [REPO_ROOT]
    sources = list(iter_sources(targets))
    if not sources:
        print("check: no python sources under %s" % ", ".join(targets))
        return 1

    failures = pass_compile(sources)
    if not args.no_api:
        failures += pass_api(targets)
    if not args.no_import:
        failures += pass_import(sources)

    print("check: %s" % ("FAILED" if failures else "OK"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
