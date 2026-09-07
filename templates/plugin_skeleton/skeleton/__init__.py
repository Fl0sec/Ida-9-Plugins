"""Shared core for the skeleton IDA 9.0 plugin.

Everything reusable lives here so the entry file stays discovery, orchestration
and UI glue only, and a second plugin can import this package instead of
copying it.

Target: IDA Professional 9.0 / IDAPython 9.0 / Python 3.12.
"""

VERSION = "0.1.0-ida9"
