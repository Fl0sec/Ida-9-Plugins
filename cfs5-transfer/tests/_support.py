"""Shared helpers for the offline CFS6 tests.

Only the IDA-free modules are exercised here (`cfs5.cfs6`, `cfs5.policy`,
`cfs5.peinfo`) plus the reference resolver. Anything importing `ida_*` is out
of scope for unit tests -- `tools/check.py` covers that with stubs.
"""

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PLUGIN_DIR = os.path.join(REPO_ROOT, "cfs5-transfer")

for _path in (PLUGIN_DIR, os.path.join(REPO_ROOT, "tools")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from cfs5 import cfs6  # noqa: E402
from cfs5.policy import Candidate  # noqa: E402


BUILDS_ROOT = r"C:\Users\Kiwi\Desktop\fl0sec\ida\cs2\builds"


def dll_path(build):
    return os.path.join(BUILDS_ROOT, build, "modules", "client", "client.dll")


def have_dll(build):
    return os.path.isfile(dll_path(build))


def sample_image(name="test.dll"):
    return {
        "name": name,
        "format": "PE",
        "architecture": "x86_64",
        "timestamp": 1788412510,
        "size_of_image": 41803776,
        "sha256": "00" * 32,
    }


def entry_candidate(pattern, anchor=0x1000, func=0x1000, size=0x40, origin=None):
    tokens = pattern.split()
    return Candidate(
        mode="ENTRY", signature=pattern,
        origin=origin or "function_entry",
        byte_len=len(tokens), wildcards=tokens.count("?"),
        exact=len(tokens) - tokens.count("?"),
        anchor_ea=anchor, func_ea=func, func_size=size,
    )


def body_candidate(pattern, anchor, func=0x1000, size=0x400, origin="body_middle"):
    tokens = pattern.split()
    return Candidate(
        mode="BODY", signature=pattern, origin=origin,
        byte_len=len(tokens), wildcards=tokens.count("?"),
        exact=len(tokens) - tokens.count("?"),
        anchor_ea=anchor, func_ea=func, func_size=size,
        body_offset=anchor - func,
    )


def rel_candidate(pattern, anchor, insn_offset, disp_offset, disp_size,
                  base_offset, origin="external_call", func=0x1000, size=0x40,
                  is_data=False, target=0x1000):
    tokens = pattern.split()
    return Candidate(
        mode="REL", signature=pattern, origin=origin,
        byte_len=len(tokens), wildcards=tokens.count("?"),
        exact=len(tokens) - tokens.count("?"),
        anchor_ea=anchor, func_ea=func, func_size=size,
        target_ea=target, is_data=is_data,
        insn_offset=insn_offset, rel_offset=disp_offset,
        rel_size=disp_size, base_offset=base_offset,
    )


def write_cfs6(path, items, image=None, build_number=14177,
               build_source="path-confirmed"):
    """items: [(kind, name, [Candidate, ...]), ...] -> a CFS6 file on disk."""
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = cfs6.Cfs6Writer(handle)
        writer.write_header(image or sample_image(), build_number, build_source)
        for kind, name, candidates in items:
            iid = writer.write_item(kind, name, len(candidates), {})
            for rank, cand in enumerate(candidates):
                writer.write_candidate(iid, rank, cand)
    return path


def write_lines(path, lines):
    with open(path, "w", encoding="utf-8", newline="") as handle:
        for line in lines:
            handle.write(line)
            handle.write("\n")
    return path


def header_line(version=6):
    return (
        '{"record":"header","format":"CFS","version":%d,"schema_revision":0,'
        '"generator":{"name":"cfs5-transfer","version":"6.0.0"},'
        '"image":{"name":"test.dll","format":"PE","architecture":"x86_64",'
        '"timestamp":1,"size_of_image":2,"sha256":"ab"},'
        '"build":{"number":null,"source":"unknown"},'
        '"scoring":{"direction":"lower-is-better"}}' % version
    )
