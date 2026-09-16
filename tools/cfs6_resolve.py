"""Resolve a CFS6 file against a PE image, without IDA.

This is the **normative reference implementation** of CFS6 resolution. The IDA
importer and any external consumer (e.g. a dumper) must agree with it. If they
disagree, this file is right and they are wrong.

    python tools/cfs6_resolve.py <file.cfs> <image.dll> [--verbose] [--name N]

Exit status is 0 when every item resolved without conflict.
"""

import argparse
import os
import re
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cfs5-transfer")
)

from cfs5 import cfs6          # noqa: E402
from cfs5.peinfo import PeImage  # noqa: E402


def pattern_to_regex(pattern):
    """IDA-style "48 8B ? C0" -> a bytes regex. `?` matches any single byte."""
    parts = []
    for token in pattern.split():
        if token == "?" or token == "??":
            parts.append(b".")
        else:
            parts.append(re.escape(bytes([int(token, 16)])))
    return re.compile(b"".join(parts), re.DOTALL)


def find_unique_match(image, pattern):
    """(rva, error). A pattern matching zero or 2+ times never resolves."""
    regex = pattern_to_regex(pattern)
    hits = []
    for match in regex.finditer(image.data):
        rva = image.offset_to_rva(match.start())
        # Only executable bytes are candidate anchors; matches inside resource
        # or data sections are noise, not signature hits.
        if rva is None or not image.is_executable_rva(rva):
            continue
        hits.append(rva)
        if len(hits) > 1:
            return None, "ambiguous (>=2 matches: 0x%X, 0x%X)" % (hits[0], hits[1])
    if not hits:
        return None, "not found"
    return hits[0], None


def resolve(image, cand):
    """(target_rva, error) for one CandidateRecord against `image`."""
    match_rva, error = find_unique_match(image, cand.pattern)
    if match_rva is None:
        return None, error

    if cand.mode == "ENTRY":
        return match_rva + cand.target_delta, None

    if cand.mode == "BODY":
        # The exporter marks a BODY whose owning function is not recoverable
        # from .pdata (chunked/outlined functions, or an IDA function start
        # that is not a RUNTIME_FUNCTION begin). Such a candidate is usable by
        # IDA but not by us; skipping it is correct, not a failure of the file.
        ownership = cand.resolve.get("ownership", "pdata")
        if ownership != "pdata":
            return None, "BODY ownership is %r, not resolvable from .pdata" % ownership

        start = match_rva - cand.body_offset
        if not image.is_runtime_function_start(start):
            return None, (
                "BODY owner 0x%X is not a .pdata runtime-function start" % start
            )
        owning = image.runtime_function_containing(match_rva)
        if owning is None or owning[0] != start:
            return None, (
                "BODY match 0x%X does not lie inside the runtime function at 0x%X"
                % (match_rva, start)
            )
        return start + cand.target_delta, None

    if cand.mode == "REL":
        insn_rva = match_rva + cand.instruction_offset
        end_rva = match_rva + cand.base_offset
        field_rva = match_rva + cand.displacement_offset
        width = cand.displacement_size

        # Revalidate that the recorded field really belongs to the anchor
        # instruction. A pattern match alone is not enough to trust the target.
        if not (insn_rva <= field_rva and field_rva + width <= end_rva):
            return None, "displacement field lies outside the anchor instruction"

        raw = image.read(field_rva, width)
        if raw is None:
            return None, "displacement bytes are not mapped"

        disp = int.from_bytes(raw, "little", signed=True)
        return match_rva + cand.base_offset + disp + cand.target_delta, None

    return None, "unsupported mode %s" % cand.mode


def resolve_item(image, item):
    """(target_rva, status, details) where status is ok/conflict/unresolved."""
    results = []
    details = []
    for cand in item.candidates:
        target, error = resolve(image, cand)
        if target is None:
            details.append("rank%d/%s/%s: %s"
                           % (cand.rank, cand.mode, cand.origin, error))
        else:
            results.append((cand, target))
            details.append("rank%d/%s/%s -> 0x%X"
                           % (cand.rank, cand.mode, cand.origin, target))

    if not results:
        return None, "unresolved", details

    targets = {t for _c, t in results}
    if len(targets) > 1:
        return None, "conflict", details

    return results[0][1], "ok", details


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cfs", help="a .cfs (CFS6 JSONL) file")
    parser.add_argument("image", help="the PE to resolve against")
    parser.add_argument("--name", action="append", default=[],
                        help="only resolve these item names (repeatable)")
    parser.add_argument("--verbose", action="store_true",
                        help="print every candidate, not just the outcome")
    args = parser.parse_args(argv)

    loaded = cfs6.load_cfs6(args.cfs, log=lambda t: print("  ! %s" % t))
    image = PeImage.from_path(args.image)

    print("file:   %s" % args.cfs)
    print("source: %s" % loaded.describe_source())
    print("image:  %s arch=%s size=0x%X pdata=%d entries"
          % (image.name, image.architecture, image.size_of_image,
             image.runtime_function_count))
    print("-" * 72)

    wanted = set(args.name)
    counts = {"ok": 0, "conflict": 0, "unresolved": 0}
    confirmed = 0

    for item in loaded.items:
        if wanted and item.name not in wanted:
            continue

        target, status, details = resolve_item(image, item)
        counts[status] += 1

        if status == "ok":
            agreed = sum(1 for d in details if "->" in d)
            if agreed > 1:
                confirmed += 1
            print("OK        %-44s 0x%-8X (%d/%d candidates)"
                  % (item.name, target, agreed, len(item.candidates)))
        elif status == "conflict":
            print("CONFLICT  %-44s candidates disagree" % item.name)
        else:
            print("MISSING   %-44s no candidate resolved" % item.name)

        if args.verbose or status != "ok":
            for line in details:
                print("            %s" % line)

    print("-" * 72)
    print("resolved=%d confirmed-by-2+=%d conflict=%d unresolved=%d"
          % (counts["ok"], confirmed, counts["conflict"], counts["unresolved"]))
    return 0 if counts["conflict"] == 0 and counts["unresolved"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
