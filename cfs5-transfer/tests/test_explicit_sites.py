"""Pinned candidates and the failure diagnosis.

Both exist for the same reason: an item that automatic discovery cannot anchor
used to produce one useless sentence ("no unique signature") and no way to
supply the answer by hand. These are the rules for the two halves of that fix
-- what a caller-supplied anchor is guaranteed, and what a failure is required
to say.
"""

import unittest

from _support import body_candidate, entry_candidate, rel_candidate

from cfs5 import cfs6, policy


def _explicit(pattern, anchor=0x5000):
    return rel_candidate(
        pattern, anchor, 0, 3, 4, 7,
        origin=policy.ORIGIN_EXPLICIT_SITE, target=0x1000,
    )


class TestPinnedCandidates(unittest.TestCase):
    def test_pinned_is_kept_even_when_every_slot_is_contested(self):
        # Four cheap discovered candidates would fill the export cap on their
        # own; the explicit one must still be in the file.
        pool = [
            entry_candidate(" ".join(["90"] * 8)),
            rel_candidate(" ".join(["A1"] * 8), 0x2000, 0, 3, 4, 7),
            body_candidate(" ".join(["B2"] * 8), 0x1100),
            body_candidate(" ".join(["C3"] * 8), 0x1200, origin="body_late"),
        ]
        pinned = _explicit(" ".join(["EE"] * 40))

        selected = policy.select_function_candidates(pool, pinned=[pinned])

        self.assertIn(pinned, selected)
        self.assertLessEqual(len(selected), policy.MAX_EXPORTED_CANDIDATES)

    def test_pinned_wins_against_a_better_score(self):
        # The pinned candidate is deliberately the worst by score: long and
        # heavily wildcarded. Scoring is a guess about the next build and must
        # not be allowed to discard evidence supplied on purpose.
        pinned = _explicit(" ".join(["EE"] * 20 + ["?"] * 20))
        cheap = entry_candidate(" ".join(["90"] * 6))

        selected = policy.select_function_candidates(
            [cheap], max_count=1, pinned=[pinned]
        )

        self.assertEqual(selected, [pinned])

    def test_pinned_comes_first(self):
        pinned = _explicit(" ".join(["EE"] * 30))
        selected = policy.select_function_candidates(
            [entry_candidate(" ".join(["90"] * 6))], pinned=[pinned]
        )
        self.assertIs(selected[0], pinned)

    def test_an_identical_discovered_pattern_is_not_exported_twice(self):
        pattern = " ".join(["EE"] * 12)
        pinned = _explicit(pattern)
        selected = policy.select_function_candidates(
            [body_candidate(pattern, 0x1100)], pinned=[pinned]
        )
        self.assertEqual([c.signature for c in selected], [pinned.signature])

    def test_no_pinned_means_the_previous_behaviour_exactly(self):
        pool = [
            entry_candidate(" ".join(["90"] * 8)),
            rel_candidate(" ".join(["A1"] * 8), 0x2000, 0, 3, 4, 7),
            body_candidate(" ".join(["B2"] * 8), 0x1100),
        ]
        self.assertEqual(
            policy.select_function_candidates(pool),
            policy.select_function_candidates(pool, pinned=()),
        )


class TestDiagnosis(unittest.TestCase):
    def _coverage(self, **axes):
        base = {
            policy.AXIS_ENTRY: cfs6.COV_NONE_UNIQUE,
            policy.AXIS_EXTERNAL_REL: cfs6.COV_NONE_UNIQUE,
            policy.AXIS_BODY: cfs6.COV_NONE_UNIQUE,
        }
        base.update(axes)
        return base

    def test_a_covered_axis_reports_selected_and_nothing_else(self):
        diagnosis = policy.diagnose_function(
            self._coverage(**{policy.AXIS_ENTRY: cfs6.COV_SELECTED}), {}
        )
        self.assertEqual(
            diagnosis[policy.AXIS_ENTRY]["reason"], policy.WHY_SELECTED
        )

    def test_many_identical_prologues_are_named_a_clone_family(self):
        # The distinction that matters: no longer prefix will ever work, so
        # the answer is a structural anchor, not more searching.
        diagnosis = policy.diagnose_function(
            self._coverage(), {"entry_matches": 9}
        )
        entry = diagnosis[policy.AXIS_ENTRY]
        self.assertEqual(entry["reason"], policy.WHY_CLONE_FAMILY)
        self.assertEqual(entry["matches"], 9)
        self.assertIn("at least", entry["detail"])

    def test_a_single_leftover_match_is_not_a_clone_family(self):
        diagnosis = policy.diagnose_function(
            self._coverage(), {"entry_matches": 1}
        )
        self.assertEqual(
            diagnosis[policy.AXIS_ENTRY]["reason"], policy.WHY_NO_UNIQUE_WINDOW
        )

    def test_no_references_is_distinct_from_references_that_did_not_work(self):
        nothing = policy.diagnose_function(self._coverage(), {"xref_count": 0})
        some = policy.diagnose_function(
            self._coverage(), {"xref_count": 12, "xrefs_tested": 6}
        )
        self.assertEqual(
            nothing[policy.AXIS_EXTERNAL_REL]["reason"], policy.WHY_NO_XREFS
        )
        self.assertEqual(
            some[policy.AXIS_EXTERNAL_REL]["reason"],
            policy.WHY_XREFS_NOT_UNIQUE,
        )
        self.assertIn("12", some[policy.AXIS_EXTERNAL_REL]["detail"])

    def test_an_address_taken_callee_is_not_reported_as_unreferenced(self):
        # A `lea`-passed callback has no call site but is plainly referenced;
        # saying "nothing references it" would send the reader looking for
        # the wrong thing.
        diagnosis = policy.diagnose_function(
            self._coverage(), {"xref_count": 0, "data_xref_count": 1}
        )
        rel = diagnosis[policy.AXIS_EXTERNAL_REL]
        self.assertEqual(rel["reason"], policy.WHY_DATA_XREFS_ONLY)
        self.assertEqual(rel["data_xref_count"], 1)

    def test_a_body_anchor_outside_pdata_is_reported_as_such(self):
        near = [{"offset": 0x37, "byte_len": 36, "ownership": "ida-only"}]
        diagnosis = policy.diagnose_function(
            self._coverage(), {"body_near_miss": near}
        )
        body = diagnosis[policy.AXIS_BODY]
        self.assertEqual(body["reason"], policy.WHY_OUTSIDE_PDATA)
        self.assertEqual(body["near_miss"], near)

    def test_an_axis_that_does_not_apply_is_not_a_failure(self):
        diagnosis = policy.diagnose_function(
            {policy.AXIS_ENTRY: cfs6.COV_NOT_APPLICABLE}, {}
        )
        self.assertEqual(
            diagnosis[policy.AXIS_ENTRY]["reason"], policy.WHY_NOT_ATTEMPTED
        )


class TestFunctionSearch(unittest.TestCase):
    def _failed(self):
        coverage = {
            policy.AXIS_ENTRY: cfs6.COV_NONE_UNIQUE,
            policy.AXIS_EXTERNAL_REL: cfs6.COV_NONE_UNIQUE,
            policy.AXIS_BODY: cfs6.COV_NONE_UNIQUE,
        }
        return policy.FunctionSearch(
            coverage=coverage,
            diagnosis=policy.diagnose_function(coverage, {
                "entry_matches": 9,
                "xref_count": 0,
                "body_near_miss": [{"offset": 0x37, "ownership": "ida-only"}],
            }),
        )

    def test_failure_reason_names_every_axis_and_its_cause(self):
        reason = self._failed().failure_reason()
        self.assertIn(policy.WHY_CLONE_FAMILY, reason)
        self.assertIn(policy.WHY_NO_XREFS, reason)
        self.assertIn(policy.WHY_OUTSIDE_PDATA, reason)

    def test_a_covered_axis_is_not_mentioned_in_the_failure_reason(self):
        coverage = {policy.AXIS_ENTRY: cfs6.COV_SELECTED,
                    policy.AXIS_BODY: cfs6.COV_NONE_UNIQUE}
        search = policy.FunctionSearch(
            candidates=[entry_candidate(" ".join(["90"] * 8))],
            coverage=coverage,
            diagnosis=policy.diagnose_function(coverage, {}),
        )
        self.assertNotIn(policy.AXIS_ENTRY, search.failure_reason())

    def test_near_misses_are_flattened_with_their_axis(self):
        near = self._failed().near_misses
        self.assertEqual(len(near), 1)
        self.assertEqual(near[0]["axis"], policy.AXIS_BODY)
        self.assertEqual(near[0]["offset"], 0x37)

    def test_truthiness_follows_the_candidates(self):
        self.assertFalse(self._failed())
        self.assertTrue(policy.FunctionSearch(
            candidates=[entry_candidate(" ".join(["90"] * 8))]
        ))


if __name__ == "__main__":
    unittest.main()
