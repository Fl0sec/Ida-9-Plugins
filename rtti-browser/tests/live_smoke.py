"""Disposable IDA 9.4 smoke test for the optimized MSVC fixture.

Run through ``idat -A -S<path-to-this-script> <fixture.exe>``. The test scans,
persists, rebases, reloads, and revalidates the snapshot before exiting IDA.
"""

import json
import os
import sys
import traceback

import ida_auto
import ida_pro
import ida_segment


_TESTS = os.path.dirname(os.path.abspath(__file__))
_PLUGIN = os.path.dirname(_TESTS)
if _PLUGIN not in sys.path:
    sys.path.insert(0, _PLUGIN)

from rttibrowser.scanner import RttiScanner
from rttibrowser import store


def _run():
    ida_auto.auto_wait()
    with open(os.path.join(_TESTS, "fixture-golden.json"), "r") as handle:
        golden = json.load(handle)

    identity = store.current_identity()
    snapshot = RttiScanner().scan(identity, deep_scan=True)
    names = {record.class_name for record in snapshot.records}
    missing = set(golden["required_classes"]) - names
    assert not missing, "missing RTTI classes: %s" % sorted(missing)
    assert len(snapshot.records) >= golden["minimum_vtables"]

    diamond = [record for record in snapshot.records
               if record.class_name == "Diamond"]
    assert diamond, "Diamond has no validated vtable"
    base_names = [base.name for base in diamond[0].bases]
    assert base_names == golden["required_diamond_bases"], base_names

    ok, reason = store.save(snapshot)
    assert ok, reason
    result = ida_segment.rebase_program(0x100000, ida_segment.MSF_FIXONCE)
    assert result == 0, "rebase failed with code %r" % result

    rebased_identity = store.current_identity()
    assert rebased_identity == identity, "rebase changed cache identity"
    loaded, reason = store.load(rebased_identity)
    assert loaded is not None, reason
    scanner = RttiScanner()
    for record in loaded.records:
        valid, reason = scanner.validate_anchor(record)
        assert valid, "%s: %s" % (record.class_name, reason)
    print("RTTI_BROWSER_LIVE_OK vtables=%d" % len(loaded.records))


def main():
    try:
        _run()
    except Exception:
        traceback.print_exc()
        ida_pro.qexit(1)
    else:
        ida_pro.qexit(0)


if __name__ == "__main__":
    main()
