# RTTI Browser (IDA 9.4)

RTTI Browser is a read-only, cached replacement for the browsing part of
Class Informer. It discovers validated Microsoft C++ RTTI, displays class
hierarchies and subobject vtables, and provides searchable virtual-method
ownership views without changing names, types, comments, or bytes.

The RTTI validation primitives are extracted from the MSVC RTTI layer already
used by this repository's `ida-pro-mcp` and CFS plugins. The chooser workflow
is informed by the MIT-licensed IDA Class Informer reference implementation.

## Use

Open an analyzed PE database and select **Edit → Plugins → RTTI Browser**, or
press **Ctrl+Shift+3**. The first launch performs a cancellable scan. Later
launches load the checksummed snapshot stored inside the IDB and validate its
class anchors before showing it.

The Classes window opens in a compact **Relevant classes** mode that hides
compiler-generated lambdas, anonymous/local types, and unresolved decorated
names. **Show all RTTI** restores every validated record. IDA's fuzzy quick
filter and native column sorts remain available. Enter or double-click a class
to open its virtual methods. The popup commands show full unabridged details,
jump to the vtable or complete object locator, build the global virtual-method
ownership index, show cache information, or explicitly rescan.

Method rows are identified by `(class, subobject offset, vtable, slot)`.
Function names and targets are read from the current IDB when the method view
opens and then preformatted once, so repainting and filtering large method
tables performs no IDA name lookups. Reopen a method view after renaming.

## Cache safety

The snapshot stores RVAs and an input/segment-layout identity, so a pure image
rebase does not require a rescan. A commit marker and SHA-256 checksum reject
interrupted writes. Startup validates COL, hierarchy, vtable, and method-bound
anchors; individual method targets are validated lazily when requested.

## Verification

```powershell
Push-Location rtti-browser
python -m unittest discover -s tests
Pop-Location
python tools/check.py rtti-browser
pwsh tools/deploy.ps1 rtti-browser
```

The fixture source is intended for disposable x86/x64 MSVC `/GR /O2` builds.
Do not commit generated executables or IDA databases.
