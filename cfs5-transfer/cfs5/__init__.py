"""Shared core for the CFS6 exporter/importer IDA 9.0 plugins.

This package holds every primitive shared between the two plugin entry files
(signature building, instruction decoding, binary type transport and the .cfs
file format) so neither plugin duplicates the other.

The package name stays `cfs5` -- it is the plugins' import identity, not the
format version. The format the plugins read and write is CFS6; see
`cfs6.py` and docs/cfs6-format.md.

Target: IDA Professional 9.0 / IDAPython 9.0 / Python 3.12.
"""

VERSION = "6.2.0-ida9"
