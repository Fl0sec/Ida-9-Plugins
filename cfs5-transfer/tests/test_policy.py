"""Candidate scoring, deduplication, ranking and diversity selection."""

import random
import unittest

from _support import body_candidate, entry_candidate, rel_candidate

from cfs5 import policy


class TestScoring(unittest.TestCase):
    def test_lower_score_is_better_shorter_wins(self):
        short = entry_candidate(" ".join(["90"] * 8))
        long = entry_candidate(" ".join(["90"] * 20))
        self.assertLess(short.score, long.score)

    def test_wildcards_cost_less_than_length(self):
        wild = entry_candidate(" ".join(["90"] * 7 + ["?"]))
        longer = entry_candidate(" ".join(["90"] * 9))
        self.assertLess(wild.score, longer.score)

    def test_mode_penalty_breaks_ties(self):
        pattern = " ".join(["90"] * 10)
        entry = entry_candidate(pattern)
        rel = rel_candidate(pattern, 0x2000, 0, 1, 4, 5)
        body = body_candidate(pattern, 0x1100)
        self.assertLess(entry.score, rel.score)
        self.assertLess(rel.score, body.score)


class TestAxes(unittest.TestCase):
    def test_axis_classification(self):
        self.assertEqual(entry_candidate("90 90 90 90 90 90").axis, "entry")
        self.assertEqual(body_candidate("90 90 90 90 90 90", 0x1100).axis, "body")
        ext = rel_candidate("90 90 90 90 90 90", 0x2000, 0, 1, 4, 5)
        self.assertEqual(ext.axis, "external_rel")
        selfish = rel_candidate(
            "90 90 90 90 90 90", 0x2000, 0, 1, 4, 5, origin="self_call"
        )
        self.assertEqual(selfish.axis, "self_rel")
        data = rel_candidate(
            "90 90 90 90 90 90", 0x2000, 0, 1, 4, 5, origin="data_reference"
        )
        self.assertEqual(data.axis, "external_rel")

    def test_body_origin_for_position(self):
        self.assertEqual(policy.body_origin_for_position(0, 3), "body_early")
        self.assertEqual(policy.body_origin_for_position(1, 3), "body_middle")
        self.assertEqual(policy.body_origin_for_position(2, 3), "body_late")
        self.assertEqual(policy.body_origin_for_position(0, 1), "body_middle")


class _FakeOwnership:
    """Stands in for image.BodyOwnership without touching IDA."""

    def __init__(self, span):
        self.span = span

    def primary_span(self, _func_ea):
        return self.span


def _insns(count, start=0x1000, size=4):
    return [{"ea": start + i * size, "size": size} for i in range(count)]


class TestPrimaryChunkLimit(unittest.TestCase):
    def test_no_ownership_means_whole_body(self):
        insns = _insns(40)
        self.assertEqual(policy.primary_chunk_limit(insns, 0x1000, None), 40)

    def test_unknown_span_means_whole_body(self):
        insns = _insns(40)
        own = _FakeOwnership(None)
        self.assertEqual(policy.primary_chunk_limit(insns, 0x1000, own), 40)

    def test_limits_to_the_primary_chunk(self):
        # 40 instructions of 4 bytes; the .pdata chunk covers the first 10.
        insns = _insns(40)
        own = _FakeOwnership((0x1000, 0x1000 + 40))
        self.assertEqual(policy.primary_chunk_limit(insns, 0x1000, own), 10)

    def test_whole_body_inside_the_chunk_is_unrestricted(self):
        insns = _insns(40)
        own = _FakeOwnership((0x1000, 0x1000 + 1000))
        self.assertEqual(policy.primary_chunk_limit(insns, 0x1000, own), 40)

    def test_too_short_a_prefix_falls_back_to_the_whole_body(self):
        # A 2-instruction chunk cannot yield distinct early/middle/late samples;
        # better to sample the whole body and label the results ida-only.
        insns = _insns(40)
        own = _FakeOwnership((0x1000, 0x1000 + 8))
        self.assertEqual(policy.primary_chunk_limit(insns, 0x1000, own), 40)

    def test_sampling_within_the_limit_stays_in_the_chunk(self):
        insns = _insns(40)
        own = _FakeOwnership((0x1000, 0x1000 + 40))
        limit = policy.primary_chunk_limit(insns, 0x1000, own)
        # Mirrors what find_body_candidates does with the limit.
        n = limit
        sampled = [max(1, n // 4), max(1, n // 2), max(1, (3 * n) // 4)]
        for idx in sampled:
            self.assertLess(insns[idx]["ea"], 0x1000 + 40)


class TestDedup(unittest.TestCase):
    def test_identical_patterns_collapse(self):
        a = entry_candidate("48 8B C4 90 90 90", anchor=0x1000)
        b = entry_candidate("48 8B C4 90 90 90", anchor=0x1000)
        self.assertEqual(len(policy.dedup_and_order([a, b])), 1)

    def test_overlap_is_not_resolved_by_dedup(self):
        """Overlap is settled in selection, where axis priority is known."""
        a = body_candidate(" ".join(["90"] * 12), anchor=0x1100)
        b = body_candidate(" ".join(["91"] * 12), anchor=0x1108)
        self.assertEqual(len(policy.dedup_and_order([a, b])), 2)

    def test_selection_drops_overlapping_bodies(self):
        a = body_candidate(" ".join(["90"] * 12), anchor=0x1100)
        b = body_candidate(" ".join(["91"] * 20), anchor=0x1108, origin="body_late")
        selected = policy.select_function_candidates([a, b])
        self.assertEqual(len(selected), 1)
        self.assertIs(selected[0], a, "the better-scoring overlapping body wins")

    def test_non_overlapping_candidates_are_kept(self):
        a = body_candidate(" ".join(["90"] * 12), anchor=0x1100)
        b = body_candidate(" ".join(["91"] * 12), anchor=0x1200, origin="body_late")
        self.assertEqual(len(policy.select_function_candidates([a, b])), 2)

    def test_ordering_is_deterministic_under_shuffling(self):
        pool = [
            entry_candidate(" ".join(["90"] * 10), anchor=0x1000),
            body_candidate(" ".join(["91"] * 10), anchor=0x1100),
            body_candidate(" ".join(["92"] * 10), anchor=0x1200, origin="body_late"),
            rel_candidate(" ".join(["93"] * 10), 0x5000, 0, 1, 4, 5),
            rel_candidate(" ".join(["94"] * 12), 0x6000, 0, 1, 4, 5),
        ]
        expected = [c.signature for c in policy.dedup_and_order(pool)]
        rng = random.Random(1234)
        for _ in range(25):
            shuffled = pool[:]
            rng.shuffle(shuffled)
            got = [c.signature for c in policy.dedup_and_order(shuffled)]
            self.assertEqual(got, expected)


class TestFunctionSelection(unittest.TestCase):
    def test_prefers_one_per_axis_over_same_region_variants(self):
        # Three short ENTRY variants would win on score alone; the policy must
        # still reach for the REL and BODY axes.
        entries = [
            entry_candidate(" ".join(["90"] * 8), anchor=0x1000),
            entry_candidate(" ".join(["91"] * 8), anchor=0x1000),
            entry_candidate(" ".join(["92"] * 8), anchor=0x1000),
        ]
        rel = rel_candidate(" ".join(["93"] * 20), 0x5000, 0, 1, 4, 5)
        body = body_candidate(" ".join(["94"] * 20), anchor=0x1200)

        selected = policy.select_function_candidates(entries + [rel, body])
        self.assertEqual({c.axis for c in selected},
                         {"entry", "external_rel", "body"})

    def test_good_entry_does_not_suppress_rel(self):
        # The CCSGOInput_CreateMove case: a strong prologue must not stop a
        # caller-side anchor from being exported.
        entry = entry_candidate(" ".join(["90"] * 8), anchor=0x1000)
        rel = rel_candidate(" ".join(["93"] * 30), 0x5000, 0, 1, 4, 5)
        selected = policy.select_function_candidates([entry, rel])
        self.assertEqual(len(selected), 2)
        self.assertIn("external_rel", {c.axis for c in selected})

    def test_ranks_are_by_score_and_contiguous(self):
        entry = entry_candidate(" ".join(["90"] * 20), anchor=0x1000)
        rel = rel_candidate(" ".join(["93"] * 8), 0x5000, 0, 1, 4, 5)
        body = body_candidate(" ".join(["94"] * 30), anchor=0x1200)
        selected = policy.select_function_candidates([entry, rel, body])
        self.assertEqual([c.mode for c in selected], ["REL", "ENTRY", "BODY"])
        scores = [c.score for c in selected]
        self.assertEqual(scores, sorted(scores))

    def test_short_overlapping_body_never_evicts_the_entry(self):
        """Regression: a BODY sampled near the prologue must yield, not win.

        A short BODY scores better than a longer ENTRY, but ENTRY is the more
        valuable anchor -- it resolves with no .pdata and no xref. Losing it to
        an overlapping BODY cost 46 ENTRY candidates in a real export.
        """
        entry = entry_candidate(" ".join(["90"] * 24), anchor=0x1000, func=0x1000)
        # Starts 2 bytes in, so it overlaps the entry window, and is shorter.
        body = body_candidate(" ".join(["91"] * 10), anchor=0x1002, func=0x1000)
        self.assertLess(body.score, entry.score)

        selected = policy.select_function_candidates([entry, body])
        self.assertIn(entry, selected)
        self.assertNotIn(body, selected)

    def test_body_far_from_the_prologue_still_survives(self):
        entry = entry_candidate(" ".join(["90"] * 24), anchor=0x1000, func=0x1000)
        body = body_candidate(" ".join(["91"] * 10), anchor=0x1100, func=0x1000)
        selected = policy.select_function_candidates([entry, body])
        self.assertIn(entry, selected)
        self.assertIn(body, selected)

    def test_selected_candidates_never_overlap(self):
        pool = [
            entry_candidate(" ".join(["90"] * 20), anchor=0x1000, func=0x1000),
            body_candidate(" ".join(["91"] * 10), anchor=0x1004, func=0x1000),
            body_candidate(" ".join(["92"] * 10), anchor=0x1008,
                           func=0x1000, origin="body_late"),
            rel_candidate(" ".join(["93"] * 10), 0x5000, 0, 1, 4, 5),
        ]
        selected = policy.select_function_candidates(pool)
        for i, a in enumerate(selected):
            for b in selected[i + 1:]:
                self.assertFalse(a.overlaps(b), "%s overlaps %s" % (a.origin, b.origin))

    def test_no_padding_when_only_one_candidate_exists(self):
        only = entry_candidate(" ".join(["90"] * 8))
        self.assertEqual(len(policy.select_function_candidates([only])), 1)

    def test_empty_input_yields_nothing(self):
        self.assertEqual(policy.select_function_candidates([]), [])

    def test_cap_is_respected(self):
        pool = [entry_candidate(" ".join(["90"] * 8), anchor=0x1000)]
        for i in range(8):
            pool.append(body_candidate(
                " ".join(["%02X" % (0x40 + i)] * 10),
                anchor=0x2000 + i * 0x100,
                origin="body_%d" % i,
            ))
        selected = policy.select_function_candidates(pool)
        self.assertLessEqual(len(selected), policy.MAX_EXPORTED_CANDIDATES)

    def test_self_call_only_used_when_no_external_rel(self):
        entry = entry_candidate(" ".join(["90"] * 8), anchor=0x1000)
        selfish = rel_candidate(
            " ".join(["93"] * 10), 0x5000, 0, 1, 4, 5, origin="self_call"
        )
        selected = policy.select_function_candidates([entry, selfish])
        self.assertIn("self_rel", {c.axis for c in selected})

        external = rel_candidate(" ".join(["94"] * 10), 0x7000, 0, 1, 4, 5)
        selected = policy.select_function_candidates([entry, selfish, external])
        axes = {c.axis for c in selected}
        self.assertIn("external_rel", axes)
        self.assertNotIn("self_rel", axes)


class TestGlobalSelection(unittest.TestCase):
    def test_takes_distinct_anchor_sites_up_to_cap(self):
        pool = [
            rel_candidate(
                " ".join(["%02X" % (0x40 + i)] * 10), 0x5000 + i * 0x100,
                0, 1, 4, 5, origin="data_reference", is_data=True,
            )
            for i in range(6)
        ]
        selected = policy.select_global_candidates(pool)
        self.assertEqual(len(selected), policy.MAX_GLOBAL_CANDIDATES)
        self.assertEqual(len({c.anchor_ea for c in selected}), len(selected))


class TestCoverage(unittest.TestCase):
    def test_reports_selected_and_none_unique(self):
        entry = entry_candidate(" ".join(["90"] * 8))
        coverage = policy.coverage_for([entry], {"entry", "external_rel", "body"})
        self.assertEqual(coverage["entry"], "selected")
        self.assertEqual(coverage["external_rel"], "none_unique")
        self.assertEqual(coverage["body"], "none_unique")

    def test_unattempted_axis_is_not_applicable(self):
        rel = rel_candidate(
            " ".join(["90"] * 8), 0x5000, 0, 1, 4, 5, origin="data_reference"
        )
        coverage = policy.coverage_for([rel], {"external_rel"})
        self.assertEqual(coverage["entry"], "not_applicable")
        self.assertEqual(coverage["body"], "not_applicable")
        self.assertEqual(coverage["external_rel"], "selected")

    def test_self_rel_is_reported_honestly(self):
        selfish = rel_candidate(
            " ".join(["90"] * 8), 0x5000, 0, 1, 4, 5, origin="self_call"
        )
        coverage = policy.coverage_for([selfish], {"entry", "external_rel", "body"})
        self.assertEqual(coverage["external_rel"], "none_unique")
        self.assertEqual(coverage["self_rel"], "selected")


class TestSerializationFields(unittest.TestCase):
    def test_rel_resolve_object(self):
        rel = rel_candidate("E8 ? ? ? ? 90", 0x5000, 0, 1, 4, 5)
        self.assertEqual(rel.resolve_object(), {
            "instruction_offset": 0,
            "displacement_offset": 1,
            "displacement_size": 4,
            "base_offset": 5,
        })

    def test_body_resolve_and_source(self):
        body = body_candidate(" ".join(["90"] * 10), anchor=0x1041, func=0x1000)
        self.assertEqual(body.resolve_object(), {"ownership": "pdata"})
        body.ownership = "ida-only"
        self.assertEqual(body.resolve_object(), {"ownership": "ida-only"})
        body.ownership = "pdata"
        source = body.source_object(imagebase=0x1000)
        self.assertEqual(source["body_offset"], 0x41)
        self.assertEqual(source["function_rva"], 0)
        self.assertEqual(source["anchor_rva"], 0x41)

    def test_global_source_uses_target_rva(self):
        glob = rel_candidate(
            " ".join(["90"] * 8), 0x5000, 0, 1, 4, 5,
            origin="data_reference", is_data=True, target=0x9000,
        )
        source = glob.source_object(imagebase=0x1000)
        self.assertEqual(source["target_rva"], 0x8000)
        self.assertNotIn("function_rva", source)


if __name__ == "__main__":
    unittest.main()
