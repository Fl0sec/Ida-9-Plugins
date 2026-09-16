"""Conflict and agreement semantics for multi-candidate items.

Exercised through the reference resolver against the real 14181 client.dll, so
these assert the behaviour a dumper must reproduce: independent candidates that
agree are evidence, and candidates that disagree are a conflict that resolves to
nothing rather than to whichever one ranked first.
"""

import unittest

from _support import dll_path, have_dll

from cfs5 import cfs6
from cfs5.peinfo import PeImage

import cfs6_resolve


CONVARREF_PATTERN = "0F 28 F0 E8 ? ? ? ? 48 8B 6C 24 50"
CONVARREF_TARGET = 0x167050


def _candidate(rank, mode, pattern, resolve=None, source=None):
    return cfs6.CandidateRecord(
        line_no=rank, item="fn:x", rank=rank, mode=mode, pattern=pattern,
        origin="test", resolve=resolve or {}, source=source or {},
    )


def _rel_candidate(rank=0):
    return _candidate(rank, "REL", CONVARREF_PATTERN, resolve={
        "instruction_offset": 3,
        "displacement_offset": 4,
        "displacement_size": 4,
        "base_offset": 8,
    })


class _Item:
    """Minimal stand-in for cfs6.ItemRecord."""

    def __init__(self, name, candidates):
        self.name = name
        self.candidates = candidates


@unittest.skipUnless(have_dll("14181"), "build 14181 client.dll is not present")
class TestConflictSemantics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = PeImage.from_path(dll_path("14181"))

    def _unique_entry_pattern_at(self, rva, length=16):
        """Shortest unique literal-byte ENTRY pattern starting at `rva`."""
        for size in range(length, 64):
            raw = self.image.read(rva, size)
            self.assertIsNotNone(raw, "cannot read %d bytes at 0x%X" % (size, rva))
            pattern = " ".join("%02X" % b for b in raw)
            hit, error = cfs6_resolve.find_unique_match(self.image, pattern)
            if error is None and hit == rva:
                return pattern
        self.fail("no unique ENTRY pattern at 0x%X" % rva)

    def test_two_independent_candidates_agree(self):
        entry = _candidate(1, "ENTRY", self._unique_entry_pattern_at(CONVARREF_TARGET))
        item = _Item("ConVarRef_GetFloat", [_rel_candidate(0), entry])

        target, status, details = cfs6_resolve.resolve_item(self.image, item)
        self.assertEqual(status, "ok")
        self.assertEqual(target, CONVARREF_TARGET)
        self.assertEqual(sum(1 for d in details if "->" in d), 2)

    def test_disagreeing_candidates_are_a_conflict_not_rank_zero_wins(self):
        # A perfectly valid ENTRY pattern -- for a different function.
        other_rva = self._some_other_function_rva()
        entry = _candidate(1, "ENTRY", self._unique_entry_pattern_at(other_rva))
        item = _Item("ConVarRef_GetFloat", [_rel_candidate(0), entry])

        target, status, _details = cfs6_resolve.resolve_item(self.image, item)
        self.assertEqual(status, "conflict")
        self.assertIsNone(target, "a conflict must not silently pick rank 0")

    def test_conflict_detail_names_every_candidate(self):
        other_rva = self._some_other_function_rva()
        entry = _candidate(1, "ENTRY", self._unique_entry_pattern_at(other_rva))
        item = _Item("ConVarRef_GetFloat", [_rel_candidate(0), entry])

        _target, _status, details = cfs6_resolve.resolve_item(self.image, item)
        self.assertEqual(len(details), 2)
        self.assertIn("0x%X" % CONVARREF_TARGET, " ".join(details))
        self.assertIn("0x%X" % other_rva, " ".join(details))

    def test_one_failing_candidate_does_not_block_the_survivor(self):
        dead = _candidate(1, "ENTRY", " ".join(["CC"] * 24))
        item = _Item("ConVarRef_GetFloat", [_rel_candidate(0), dead])

        target, status, details = cfs6_resolve.resolve_item(self.image, item)
        self.assertEqual(status, "ok")
        self.assertEqual(target, CONVARREF_TARGET)
        self.assertEqual(sum(1 for d in details if "->" in d), 1)

    def test_all_failing_is_unresolved(self):
        item = _Item("nope", [
            _candidate(0, "ENTRY", " ".join(["CC"] * 24)),
            _candidate(1, "ENTRY", " ".join(["CD"] * 24)),
        ])
        target, status, _details = cfs6_resolve.resolve_item(self.image, item)
        self.assertEqual(status, "unresolved")
        self.assertIsNone(target)

    def test_ambiguous_pattern_never_resolves(self):
        """A non-unique match is a hard failure, never 'take the first hit'."""
        _hit, error = cfs6_resolve.find_unique_match(self.image, "48")
        self.assertIsNotNone(error)
        self.assertIn("ambiguous", error)

    def _some_other_function_rva(self):
        """A .pdata function start that is not the ConVarRef target."""
        for start, _end in self.image.pdata_index._ranges:
            if start != CONVARREF_TARGET and self.image.is_executable_rva(start):
                if self.image.read(start, 24) is not None:
                    return start
        self.fail("no usable second function found")


if __name__ == "__main__":
    unittest.main()
