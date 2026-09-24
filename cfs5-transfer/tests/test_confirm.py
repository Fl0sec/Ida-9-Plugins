"""Offline tests for the confirm-signature primitive.

Only the `ida_*`-free half is reachable here: the `.pdata` chain walk
(`peinfo.PdataIndex.chain_end`) and the two policy rules (`confirm_min_exact`,
`rank_confirm_windows`). The finder itself (`cfs5.confirm`) and the relaxed
tokenizer touch IDA, so they are covered by `tools/check.py` plus an in-IDA
probe -- see the module docstring in `cfs5/confirm.py`.
"""

import unittest

from _support import PLUGIN_DIR  # noqa: F401  (path setup)

from cfs5 import policy
from cfs5.peinfo import PdataIndex


class ChainEndTests(unittest.TestCase):
    """The scan range a consumer will actually cover."""

    def test_single_entry_function(self):
        index = PdataIndex([(0x1000, 0x1040)])
        self.assertEqual(index.chain_end(0x1000), 0x1040)

    def test_joins_adjacent_entries(self):
        # The case that motivates this: 0x83F290 in cs2 client.dll is two
        # abutting RUNTIME_FUNCTIONs, and both must be scanned.
        index = PdataIndex([(0x1000, 0x1020), (0x1020, 0x1060)])
        self.assertEqual(index.chain_end(0x1000), 0x1060)

    def test_joins_three_adjacent_entries(self):
        index = PdataIndex([(0x1000, 0x1020), (0x1020, 0x1060), (0x1060, 0x1070)])
        self.assertEqual(index.chain_end(0x1000), 0x1070)

    def test_stops_at_a_gap(self):
        index = PdataIndex([(0x1000, 0x1020), (0x1024, 0x1060)])
        self.assertEqual(index.chain_end(0x1000), 0x1020)

    def test_non_begin_rva_is_none(self):
        # Mid-function, and the *second* entry's begin reached from the first:
        # neither is a chain start, and guessing one would attribute a
        # neighbour's bytes to this function.
        index = PdataIndex([(0x1000, 0x1020), (0x1020, 0x1060)])
        self.assertIsNone(index.chain_end(0x1008))
        self.assertIsNone(index.chain_end(0x0FFF))

    def test_inner_entry_starts_its_own_chain(self):
        index = PdataIndex([(0x1000, 0x1020), (0x1020, 0x1060)])
        self.assertEqual(index.chain_end(0x1020), 0x1060)

    def test_empty_index(self):
        self.assertIsNone(PdataIndex().chain_end(0x1000))

    def test_chain_end_is_never_shorter_than_the_owning_entry(self):
        index = PdataIndex([(0x1000, 0x1020), (0x1020, 0x1060)])
        owning = index.containing(0x1000)
        self.assertGreaterEqual(index.chain_end(0x1000), owning[1])


class ConfirmFloorTests(unittest.TestCase):

    def test_no_exact_byte_floor_applies(self):
        # The image-wide floors exist for image-wide uniqueness; a confirm
        # signature is matched inside one function and must not inherit them.
        for length in (4, 8, 10, 24, 48):
            self.assertEqual(policy.confirm_min_exact(length), 0)
        self.assertLess(policy.confirm_min_exact(24), policy.candidate_min_exact(24))
        self.assertLess(policy.confirm_min_exact(24), policy.value_min_exact(24))


def _window(offset, byte_len, image_matches, wildcards=0, tokenization=None):
    return {
        "signature": "?? " * byte_len,
        "offset": offset,
        "byte_len": byte_len,
        "wildcards": wildcards,
        "tokenization": tokenization or policy.TOKENIZATION_RELAXED,
        "image_matches": image_matches,
    }


class RankConfirmWindowsTests(unittest.TestCase):

    def test_image_unique_beats_scan_unique_at_equal_length(self):
        ranked = policy.rank_confirm_windows([
            _window(0x10, 16, image_matches=3),
            _window(0x20, 16, image_matches=1),
        ])
        self.assertEqual(ranked[0]["offset"], 0x20)

    def test_image_unique_beats_a_shorter_ambiguous_window(self):
        # The clone-family defence: a relaxed pattern that also matches inside
        # a sibling would confirm the wrong function if the locator drifted,
        # so length never buys its way past that.
        ranked = policy.rank_confirm_windows([
            _window(0x10, 8, image_matches=2),
            _window(0x20, 48, image_matches=1),
        ])
        self.assertEqual(ranked[0]["offset"], 0x20)

    def test_shorter_wins_among_image_unique_windows(self):
        ranked = policy.rank_confirm_windows([
            _window(0x10, 48, image_matches=1),
            _window(0x20, 15, image_matches=1),
        ])
        self.assertEqual(ranked[0]["byte_len"], 15)

    def test_fewer_wildcards_breaks_a_length_tie(self):
        ranked = policy.rank_confirm_windows([
            _window(0x10, 16, image_matches=1, wildcards=9),
            _window(0x20, 16, image_matches=1, wildcards=2),
        ])
        self.assertEqual(ranked[0]["wildcards"], 2)

    def test_ordering_is_deterministic_regardless_of_input_order(self):
        windows = [
            _window(0x30, 16, image_matches=1),
            _window(0x10, 16, image_matches=1),
            _window(0x20, 8, image_matches=4),
        ]
        first = [w["offset"] for w in policy.rank_confirm_windows(windows)]
        second = [w["offset"] for w in policy.rank_confirm_windows(windows[::-1])]
        self.assertEqual(first, second)
        self.assertEqual(first[0], 0x10)

    def test_strict_and_image_unique_beats_relaxed_and_ambiguous(self):
        # The measured `notify_inventory_has_new_items` case: no relaxed window
        # is image-unique, and the strict one is unique precisely because it
        # pins the stack offsets separating it from its clone siblings.
        ranked = policy.rank_confirm_windows([
            _window(0x58, 10, image_matches=8, wildcards=1,
                    tokenization=policy.TOKENIZATION_RELAXED),
            _window(0x58, 15, image_matches=1, wildcards=0,
                    tokenization=policy.TOKENIZATION_STRICT),
        ])
        self.assertEqual(ranked[0]["tokenization"], policy.TOKENIZATION_STRICT)
        self.assertEqual(ranked[0]["image_matches"], 1)

    def test_relaxed_wins_among_equally_image_unique_windows(self):
        # Tolerance is the second key, so a longer relaxed window beats a
        # shorter strict one once both are equally discriminating.
        ranked = policy.rank_confirm_windows([
            _window(0x10, 12, image_matches=1,
                    tokenization=policy.TOKENIZATION_STRICT),
            _window(0x20, 30, image_matches=1, wildcards=6,
                    tokenization=policy.TOKENIZATION_RELAXED),
        ])
        self.assertEqual(ranked[0]["tokenization"], policy.TOKENIZATION_RELAXED)

    def test_tokenization_never_outranks_image_uniqueness(self):
        ranked = policy.rank_confirm_windows([
            _window(0x10, 8, image_matches=4,
                    tokenization=policy.TOKENIZATION_RELAXED),
            _window(0x20, 40, image_matches=1,
                    tokenization=policy.TOKENIZATION_STRICT),
        ])
        self.assertEqual(ranked[0]["image_matches"], 1)

    def test_ambiguous_windows_are_ranked_not_dropped(self):
        # When nothing is image-unique the best available answer is still
        # returned -- with its match count, so the consumer can weigh it.
        ranked = policy.rank_confirm_windows([
            _window(0x10, 32, image_matches=5),
            _window(0x20, 12, image_matches=2),
        ])
        self.assertEqual(len(ranked), 2)
        self.assertEqual(ranked[0]["offset"], 0x20)
        self.assertEqual(ranked[0]["image_matches"], 2)


class ScanBoundVocabularyTests(unittest.TestCase):

    def test_scan_bounds_is_a_closed_set(self):
        self.assertEqual(
            set(policy.SCAN_BOUNDS),
            {policy.SCAN_BOUND_PDATA_CHAIN, policy.SCAN_BOUND_IDA_EXTENT},
        )

    def test_tokenizations_is_a_closed_set(self):
        self.assertEqual(
            set(policy.TOKENIZATIONS),
            {policy.TOKENIZATION_STRICT, policy.TOKENIZATION_RELAXED},
        )

    def test_refusal_reasons_are_distinct(self):
        reasons = (
            policy.CONFIRM_NO_SCAN_RANGE,
            policy.CONFIRM_NO_INSTRUCTIONS,
            policy.CONFIRM_NO_UNIQUE_WINDOW,
        )
        self.assertEqual(len(set(reasons)), len(reasons))


if __name__ == "__main__":
    unittest.main()
