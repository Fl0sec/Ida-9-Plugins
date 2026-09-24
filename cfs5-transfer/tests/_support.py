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


def value_candidate(pattern, anchor=0x2000, insn_offset=0, field_offset=3,
                    field_size=4, operand_index=1, origin=None, value=0x1E0,
                    op=None, extra=None, func=0x2000, size=0x80):
    tokens = pattern.split()
    extract = {
        "op": op or cfs6.OP_DISP,
        "instruction_offset": insn_offset,
    }
    if (op or cfs6.OP_DISP) != cfs6.OP_CONST:
        extract.update({
            "field_offset": field_offset,
            "field_size": field_size,
            "operand_index": operand_index,
            "signed": True,
        })
    extract.update(extra or {})
    return Candidate(
        mode="VALUE", signature=pattern,
        origin=origin or cfs6.ORIGIN_STROFF_XREF,
        byte_len=len(tokens), wildcards=tokens.count("?"),
        exact=len(tokens) - tokens.count("?"),
        anchor_ea=anchor, func_ea=func, func_size=size,
        insn_offset=insn_offset, extract=extract, value=value,
    )


def vtable_candidate(pattern="48 89 44 24 ? 48 8B CB FF D7", anchor=0x1058,
                     func=0x1000, size=0x6D, vtable=0x9000, slot=19):
    tokens = pattern.split()
    return Candidate(
        mode=cfs6.MODE_VTABLE, signature=pattern,
        origin=cfs6.ORIGIN_RTTI_VTABLE_SLOT,
        byte_len=len(tokens), wildcards=tokens.count("?"),
        exact=len(tokens) - tokens.count("?"),
        anchor_ea=anchor, func_ea=func, func_size=size,
        target_ea=vtable,
        locator={
            "type_descriptor": ".?AVCCSPlayerInventory@@",
            "subobject_offset": 0,
            "slot": slot,
            "confirm_offset": anchor - func,
            "function_size": size,
            "scan_bound": cfs6.SCAN_BOUND_PDATA_CHAIN,
            "tokenization": cfs6.TOKENIZATION_STRICT,
            "image_matches": 1,
        },
    )


def write_member_cfs6(path, members, image=None, build_number=14177):
    """members: [(owner, name, expected, [Candidate, ...]), ...] -> a file."""
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = cfs6.Cfs6Writer(handle)
        writer.write_header(image or sample_image(), build_number, "user")
        for owner, name, expected, candidates in members:
            iid = writer.write_derived_value(
                cfs6.SEM_MEMBER_OFFSET, owner, name, len(candidates), {},
                expected_value=expected,
            )
            for rank, cand in enumerate(candidates):
                writer.write_candidate(iid, rank, cand)
    return path


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
