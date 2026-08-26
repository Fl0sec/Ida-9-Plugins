"""Shared core for the CFS5 exporter/importer IDA 9.0 plugins.

This package holds every primitive shared between the two plugin entry files
(signature building, instruction decoding, binary type transport and the .cfs
file format) so neither plugin duplicates the other.

Target: IDA Professional 9.0 / IDAPython 9.0 / Python 3.12.
"""

VERSION = "6.1.0-ida9"
