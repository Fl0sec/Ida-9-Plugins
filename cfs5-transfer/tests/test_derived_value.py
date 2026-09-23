"""The `derived_value` item kind: format, selection policy and resolution.

Covers the rules that make a recovered integer trustworthy -- closed
vocabularies, the origin restriction, and the refusal to let a CONST stand in
for evidence -- plus a round trip through the reference resolver so the
extraction contract is exercised end to end without IDA.
"""

import json
import os
import tempfile
import unittest

from _support import (
    entry_candidate, header_line, sample_image, value_candidate, write_lines,
    write_member_cfs6,
)

from cfs5 import cfs6
from cfs5 import declare
from cfs5 import policy
from cfs5.policy import select_value_candidates, value_coverage

import cfs6_resolve


class _TempFileCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cfs6dv")

    def tearDown(self):
        for name in os.listdir(self.dir):
            os.unlink(os.path.join(self.dir, name))
        os.rmdir(self.dir)

    def path(self, name="t.cfs"):
        return os.path.join(self.dir, name)

    def load(self, lines):
        errors = []
        loaded = cfs6.load_cfs6(
            write_lines(self.path(), lines), log=errors.append
        )
        return loaded, errors


# ---------------------------------------------------------------------------
# Item identity and round trip
# ---------------------------------------------------------------------------

class DerivedItemIdTests(unittest.TestCase):
    def test_member_id_is_owner_qualified(self):
        self.assertEqual(
            cfs6.derived_item_id(
                cfs6.SEM_MEMBER_OFFSET, "CGameSceneNode", "bone_transforms"
            ),
            "member:CGameSceneNode::bone_transforms",
        )

    def test_same_field_name_on_two_types_gets_two_ids(self):
        a = cfs6.derived_item_id(cfs6.SEM_MEMBER_OFFSET, "A", "m_pNext")
        b = cfs6.derived_item_id(cfs6.SEM_MEMBER_OFFSET, "B", "m_pNext")
        self.assertNotEqual(a, b)

    def test_each_semantic_gets_a_distinct_prefix(self):
        prefixes = {
            cfs6.derived_item_id(sem, "T", "x").split(":", 1)[0]
            for sem in cfs6.VALID_SEMANTICS
        }
        self.assertEqual(len(prefixes), len(cfs6.VALID_SEMANTICS))

    def test_unknown_semantic_is_refused(self):
        with self.assertRaises(ValueError):
            cfs6.derived_item_id("vibes", "T", "x")

    def test_owner_is_required(self):
        with self.assertRaises(ValueError):
            cfs6.derived_item_id(cfs6.SEM_MEMBER_OFFSET, "", "x")


class RoundTripTests(_TempFileCase):
    def test_member_survives_write_and_read(self):
        write_member_cfs6(self.path(), [(
            "CGameSceneNode", "bone_transforms", 0x1E0,
            [value_candidate("48 8B 8B ? ? ? ? 48 85 C9", value=0x1E0)],
        )])
        loaded = cfs6.load_cfs6(self.path())

        self.assertEqual(loaded.parse_errors, 0)
        self.assertEqual(len(loaded.derived_values()), 1)
        item = loaded.derived_values()[0]
        self.assertEqual(item.semantic, cfs6.SEM_MEMBER_OFFSET)
        self.assertEqual(item.owner, "CGameSceneNode")
        self.assertEqual(item.expected_value, 0x1E0)
        self.assertEqual(item.qualified_name, "CGameSceneNode::bone_transforms")
        self.assertEqual(len(item.candidates), 1)

        cand = item.candidates[0]
        self.assertEqual(cand.mode, "VALUE")
        self.assertEqual(cand.op, cfs6.OP_DISP)
        self.assertEqual(cand.field_offset, 3)
        self.assertEqual(cand.field_size, 4)
        self.assertEqual(cand.operand_index, 1)
        self.assertTrue(cand.field_signed)

    def test_expected_value_is_on_the_item_not_the_candidates(self):
        write_member_cfs6(self.path(), [(
            "T", "f", 0x10,
            [value_candidate("48 8B 8B ? ? ? ? 48 85 C9", value=0x10),
             value_candidate("4C 8B B3 ? ? ? ? 4D 85 F6", anchor=0x3000,
                             value=0x10)],
        )])
        with open(self.path(), "r", encoding="utf-8") as handle:
            records = [json.loads(line) for line in handle if line.strip()]

        candidates = [r for r in records if r["record"] == "candidate"]
        self.assertEqual(len(candidates), 2)
        for rec in candidates:
            self.assertNotIn("expected_value", rec.get("source", {}))

        item = [r for r in records if r["record"] == "derived_value"][0]
        self.assertEqual(item["source"]["expected_value"], 0x10)

    def test_functions_and_members_coexist_in_one_namespace(self):
        with open(self.path(), "w", encoding="utf-8", newline="") as handle:
            writer = cfs6.Cfs6Writer(handle)
            writer.write_header(sample_image(), 1, "user")
            fid = writer.write_item(cfs6.REC_FUNCTION, "Thing", 1, {})
            writer.write_candidate(fid, 0, entry_candidate("48 89 5C 24 08 57"))
            mid = writer.write_derived_value(
                cfs6.SEM_MEMBER_OFFSET, "Owner", "Thing", 1, {},
                expected_value=8,
            )
            writer.write_candidate(
                mid, 0, value_candidate("48 8B 8B ? ? ? ? 48 85 C9", value=8)
            )

        loaded = cfs6.load_cfs6(self.path())
        self.assertEqual(loaded.parse_errors, 0)
        self.assertEqual(len(loaded.functions()), 1)
        self.assertEqual(len(loaded.derived_values()), 1)

    def test_filtering_derived_values_by_semantic(self):
        write_member_cfs6(self.path(), [(
            "T", "f", 8, [value_candidate("48 8B 8B ? ? ? ? 48 85 C9", value=8)]
        )])
        loaded = cfs6.load_cfs6(self.path())
        self.assertEqual(
            len(loaded.derived_values(cfs6.SEM_MEMBER_OFFSET)), 1
        )
        self.assertEqual(
            len(loaded.derived_values(cfs6.SEM_ELEMENT_STRIDE)), 0
        )


# ---------------------------------------------------------------------------
# Reader validation
# ---------------------------------------------------------------------------

def _item_line(**overrides):
    obj = {
        "record": "derived_value",
        "id": "member:T::f",
        "name": "f",
        "owner": "T",
        "semantic": "member_offset",
        "candidate_count": 1,
        "coverage": {},
        "source": {"expected_value": 16},
    }
    obj.update(overrides)
    return json.dumps(obj)


def _cand_line(resolve=None, origin=None, mode="VALUE", item="member:T::f",
               pattern="48 8B 8B ? ? ? ? 48 85 C9"):
    base = {
        "op": "DISP", "instruction_offset": 0, "field_offset": 3,
        "field_size": 4, "operand_index": 1, "signed": True,
    }
    if resolve is not None:
        base.update(resolve)
    return json.dumps({
        "record": "candidate", "item": item, "rank": 0, "mode": mode,
        "pattern": pattern, "origin": origin or cfs6.ORIGIN_STROFF_XREF,
        "score": 100, "source": {}, "resolve": base,
    })


class ReaderValidationTests(_TempFileCase):
    def test_unknown_semantic_is_rejected_not_guessed(self):
        loaded, errors = self.load([
            header_line(), _item_line(semantic="element_count"),
        ])
        self.assertEqual(loaded.derived_values(), [])
        self.assertEqual(loaded.parse_errors, 1)
        self.assertTrue(any("element_count" in e for e in errors))

    def test_member_offset_without_expected_value_is_rejected(self):
        loaded, _ = self.load([header_line(), _item_line(source={})])
        self.assertEqual(loaded.parse_errors, 1)

    def test_non_integer_expected_value_is_rejected(self):
        loaded, _ = self.load([
            header_line(), _item_line(source={"expected_value": "0x10"}),
        ])
        self.assertEqual(loaded.parse_errors, 1)

    def test_origin_outside_the_closed_set_is_rejected(self):
        loaded, errors = self.load([
            header_line(), _item_line(),
            _cand_line(origin="displacement_scan"),
        ])
        self.assertEqual(loaded.parse_errors, 1)
        self.assertTrue(any("displacement_scan" in e for e in errors))
        self.assertEqual(loaded.derived_values()[0].candidates, [])

    def test_every_sanctioned_origin_is_accepted(self):
        for origin in cfs6.VALID_VALUE_ORIGINS:
            loaded, _ = self.load([
                header_line(), _item_line(), _cand_line(origin=origin),
            ])
            self.assertEqual(loaded.parse_errors, 0, origin)
            self.assertEqual(len(loaded.derived_values()[0].candidates), 1)

    def test_unknown_extraction_op_is_rejected(self):
        loaded, _ = self.load([
            header_line(), _item_line(), _cand_line({"op": "EVAL"}),
        ])
        self.assertEqual(loaded.parse_errors, 1)

    def test_field_running_past_the_pattern_is_rejected(self):
        loaded, _ = self.load([
            header_line(), _item_line(),
            _cand_line({"field_offset": 8, "field_size": 4}),
        ])
        self.assertEqual(loaded.parse_errors, 1)

    def test_field_before_its_own_instruction_is_rejected(self):
        loaded, _ = self.load([
            header_line(), _item_line(),
            _cand_line({"instruction_offset": 5, "field_offset": 3}),
        ])
        self.assertEqual(loaded.parse_errors, 1)

    def test_odd_field_size_is_rejected(self):
        loaded, _ = self.load([
            header_line(), _item_line(), _cand_line({"field_size": 3}),
        ])
        self.assertEqual(loaded.parse_errors, 1)

    def test_operand_index_out_of_range_is_rejected(self):
        loaded, _ = self.load([
            header_line(), _item_line(), _cand_line({"operand_index": 99}),
        ])
        self.assertEqual(loaded.parse_errors, 1)

    def test_const_needs_a_value(self):
        loaded, _ = self.load([
            header_line(), _item_line(),
            _cand_line({"op": "CONST", "field_offset": 0, "field_size": 0,
                        "operand_index": 0}),
        ])
        self.assertEqual(loaded.parse_errors, 1)

    def test_const_with_a_value_is_accepted(self):
        loaded, _ = self.load([
            header_line(), _item_line(source={"expected_value": 0}),
            _cand_line({"op": "CONST", "value": 0}),
        ])
        self.assertEqual(loaded.parse_errors, 0)
        self.assertEqual(loaded.derived_values()[0].candidates[0].const_value, 0)

    def test_disp_plus_width_needs_an_access_width(self):
        loaded, _ = self.load([
            header_line(), _item_line(),
            _cand_line({"op": "DISP_PLUS_WIDTH"}),
        ])
        self.assertEqual(loaded.parse_errors, 1)

    def test_value_candidate_cannot_belong_to_a_function(self):
        func_item = json.dumps({
            "record": "function", "id": "fn:T", "name": "T",
            "candidate_count": 1, "coverage": {},
        })
        loaded, errors = self.load([
            header_line(), func_item, _cand_line(item="fn:T"),
        ])
        self.assertEqual(loaded.parse_errors, 1)
        self.assertTrue(any("cannot belong" in e for e in errors))

    def test_rel_candidate_cannot_belong_to_a_derived_value(self):
        rel = json.dumps({
            "record": "candidate", "item": "member:T::f", "rank": 0,
            "mode": "REL", "pattern": "E8 ? ? ? ? 90", "origin": "external_call",
            "score": 100, "source": {},
            "resolve": {"instruction_offset": 0, "displacement_offset": 1,
                        "displacement_size": 4, "base_offset": 5},
        })
        loaded, _ = self.load([header_line(), _item_line(), rel])
        self.assertEqual(loaded.parse_errors, 1)

    def test_a_revision_0_reader_would_skip_these_records(self):
        # Forward compatibility is the reason this is a schema revision rather
        # than a major version: unknown record kinds are counted and skipped.
        loaded, _ = self.load([
            header_line(),
            json.dumps({"record": "patch_site", "id": "patch:x", "name": "x"}),
        ])
        self.assertEqual(loaded.skipped_records, 1)
        self.assertEqual(loaded.parse_errors, 0)


# ---------------------------------------------------------------------------
# Selection policy
# ---------------------------------------------------------------------------

class ValueMinExactTests(unittest.TestCase):
    def test_value_never_inherits_the_short_rel_tier(self):
        # A lone 5-byte instruction with one wildcarded displacement byte has
        # 4 exact bytes and used to pass; unique in this build, fragile in the
        # next.
        self.assertEqual(policy.candidate_min_exact(5), 4)
        self.assertGreaterEqual(policy.value_min_exact(5), 8)

    def test_value_floor_never_drops_below_the_generic_one(self):
        for total in (4, 5, 9, 10, 16, 32, 64):
            self.assertGreaterEqual(
                policy.value_min_exact(total),
                policy.candidate_min_exact(total),
                total,
            )


class SelectValueCandidateTests(unittest.TestCase):
    def test_overlapping_sites_are_not_independent_evidence(self):
        a = value_candidate("48 8B 8B ? ? ? ? 48 85 C9", anchor=0x1000)
        b = value_candidate("8B ? ? ? ? 48 85 C9 74 10", anchor=0x1002)
        selected = select_value_candidates([a, b])
        self.assertEqual(len(selected), 1)

    def test_distinct_sites_are_all_kept(self):
        cands = [
            value_candidate("48 8B 8B ? ? ? ? 48 85 C9", anchor=0x1000),
            value_candidate("4C 8B B3 ? ? ? ? 4D 85 F6", anchor=0x2000),
            value_candidate("48 8B 93 ? ? ? ? 48 85 D2", anchor=0x3000),
        ]
        self.assertEqual(len(select_value_candidates(cands)), 3)

    def test_identical_patterns_collapse(self):
        pattern = "48 8B 8B ? ? ? ? 48 85 C9"
        cands = [
            value_candidate(pattern, anchor=0x1000),
            value_candidate(pattern, anchor=0x9000),
        ]
        self.assertEqual(len(select_value_candidates(cands)), 1)

    def test_const_is_dropped_when_real_evidence_exists(self):
        const = value_candidate(
            "48 8B 01 48 85 C0 74 20", anchor=0x1000, op=cfs6.OP_CONST,
            extra={"value": 0}, value=0,
        )
        real = value_candidate(
            "48 8B 8B ? ? ? ? 48 85 C9", anchor=0x2000, value=0,
        )
        selected = select_value_candidates([const, real])
        self.assertEqual(
            [c.extract["op"] for c in selected], [cfs6.OP_DISP]
        )

    def test_const_survives_when_it_is_all_there_is(self):
        const = value_candidate(
            "48 8B 01 48 85 C0 74 20", op=cfs6.OP_CONST,
            extra={"value": 0}, value=0,
        )
        self.assertEqual(len(select_value_candidates([const])), 1)

    def test_several_consts_collapse_to_one(self):
        # Two CONSTs would agree unconditionally; that is not confirmation,
        # and dropping them all would lose the item entirely.
        consts = [
            value_candidate("48 8B 01 48 85 C0 74 20", anchor=0x1000,
                            op=cfs6.OP_CONST, extra={"value": 0}, value=0),
            value_candidate("4C 8B 31 4D 85 F6 74 18", anchor=0x2000,
                            op=cfs6.OP_CONST, extra={"value": 0}, value=0),
        ]
        self.assertEqual(len(select_value_candidates(consts)), 1)

    def test_candidate_count_is_capped(self):
        cands = [
            value_candidate(
                "48 8B %02X ? ? ? ? 48 85 C9" % (0x80 + i), anchor=0x1000 * (i + 1)
            )
            for i in range(6)
        ]
        self.assertLessEqual(len(select_value_candidates(cands)), 3)

    def test_coverage_reports_the_single_axis_honestly(self):
        self.assertEqual(
            value_coverage([value_candidate("48 8B 8B ? ? ? ? 48 85 C9")]),
            {"value": cfs6.COV_SELECTED},
        )
        self.assertEqual(
            value_coverage([]), {"value": cfs6.COV_NONE_UNIQUE}
        )


# ---------------------------------------------------------------------------
# The declaration model
# ---------------------------------------------------------------------------

class DeclarationTests(unittest.TestCase):
    def test_member_id_matches_a_real_declaration(self):
        # The chooser asks "is this declared?" by id alone, without building a
        # Declaration; the two must not be able to drift apart.
        decl = declare.make_member("CGameTrace", "m_flFraction")
        self.assertEqual(
            declare.member_id("CGameTrace", "m_flFraction"), decl.id
        )

    def test_badaddr_site_is_normalized_to_no_site(self):
        # A sentinel stored as a real site renders as "BADADDR" in the UI and,
        # worse, is handed to candidate generation as a `selected_operand`.
        decl = declare.make_member(
            "CGameTrace", "m_flFraction",
            sites=[(0xFFFFFFFFFFFFFFFF, -1)],
        )
        self.assertEqual(decl.sites, [])
        self.assertFalse(decl.has_site)
        self.assertFalse(declare.from_dict(decl.to_dict()).has_site)

    def test_round_trip(self):
        decl = declare.make_member(
            "CGameSceneNode", "bone_transforms", member="m_pBoneTransforms",
            sites=[(0x140001000, 1)],
        )
        again = declare.from_dict(decl.to_dict())
        self.assertEqual(again.id, decl.id)
        self.assertEqual(again.member, "m_pBoneTransforms")
        self.assertEqual(again.sites, [(0x140001000, 1)])
        self.assertTrue(again.has_site)

    def test_member_defaults_to_the_canonical_name(self):
        decl = declare.make_member("T", "f")
        self.assertEqual(decl.member, "f")
        self.assertFalse(decl.has_site)

    def test_canonical_name_may_differ_from_the_ida_field(self):
        # The point of the split: a project naming convention must not force a
        # rename inside the database.
        decl = declare.make_member("T", "bone_transforms", member="m_pBones")
        self.assertEqual(decl.id, "member:T::bone_transforms")
        self.assertEqual(decl.member, "m_pBones")

    def test_names_must_be_plain_identifiers(self):
        for bad in ("", "has space", "with::colons", "9lives", "a-b"):
            with self.assertRaises(declare.DeclarationError, msg=bad):
                declare.make_member("T", bad)

    def test_owner_is_validated_too(self):
        with self.assertRaises(declare.DeclarationError):
            declare.make_member("", "f")

    def test_unknown_semantic_is_refused(self):
        with self.assertRaises(declare.DeclarationError):
            declare.Declaration("guesswork", "T", "f")

    def test_a_newer_declaration_is_refused_rather_than_misread(self):
        data = declare.make_member("T", "f").to_dict()
        data["version"] = declare.DECL_VERSION + 1
        with self.assertRaises(declare.DeclarationError):
            declare.from_dict(data)

    def test_non_dict_input_is_refused(self):
        with self.assertRaises(declare.DeclarationError):
            declare.from_dict("member:T::f")


class MultiSiteTests(unittest.TestCase):
    """Sites are evidence locations, and there can be several."""

    def test_sites_are_deduplicated_and_order_stable(self):
        decl = declare.make_member(
            "T", "f", sites=[(0x2000, 1), (0x1000, 0), (0x2000, 1)]
        )
        self.assertEqual(decl.sites, [(0x2000, 1), (0x1000, 0)])

    def test_dict_and_tuple_sites_are_both_accepted(self):
        a = declare.make_member("T", "f", sites=[{"ea": 0x1000, "op": 2}])
        b = declare.make_member("T", "f", sites=[(0x1000, 2)])
        self.assertEqual(a.sites, b.sites)

    def test_a_malformed_site_is_refused_not_ignored(self):
        for bad in ([("only-one",)], [("x", "y")], [0x1000]):
            with self.assertRaises(declare.DeclarationError):
                declare.make_member("T", "f", sites=bad)

    def test_sentinels_are_dropped_but_real_sites_survive(self):
        decl = declare.make_member(
            "T", "f", sites=[(0xFFFFFFFFFFFFFFFF, 0), (0x1000, 1), (0, 0)]
        )
        self.assertEqual(decl.sites, [(0x1000, 1)])

    def test_round_trip_preserves_every_site(self):
        decl = declare.make_member(
            "T", "f", sites=[(0x1000, 0), (0x2000, 1), (0x3000, 2)]
        )
        again = declare.from_dict(decl.to_dict())
        self.assertEqual(again.sites, decl.sites)
        self.assertEqual(again.discovery, decl.discovery)


class DiscoveryModeTests(unittest.TestCase):
    def test_sites_only_forbids_scanning(self):
        decl = declare.make_member(
            "T", "f", sites=[(0x1000, 0)],
            discovery=declare.DISCOVER_SITES_ONLY,
        )
        self.assertFalse(decl.scan_allowed)

    def test_sites_plus_auto_allows_scanning(self):
        decl = declare.make_member(
            "T", "f", sites=[(0x1000, 0)],
            discovery=declare.DISCOVER_SITES_PLUS_AUTO,
        )
        self.assertTrue(decl.scan_allowed)

    def test_no_site_falls_back_to_auto(self):
        """sites_only with no sites would export nothing, silently."""
        decl = declare.make_member(
            "T", "f", discovery=declare.DISCOVER_SITES_ONLY
        )
        self.assertEqual(decl.discovery, declare.DISCOVER_AUTO)
        self.assertTrue(decl.scan_allowed)

    def test_unknown_mode_is_refused(self):
        with self.assertRaises(declare.DeclarationError):
            declare.make_member("T", "f", sites=[(1, 0)], discovery="maybe")


class V1MigrationTests(unittest.TestCase):
    """A declaration made before multi-site must not have to be redone."""

    V1 = {
        "version": 1, "semantic": "member_offset", "owner": "CModel",
        "name": "m_nBoneCount", "member": "m_nBoneCount",
        "site_ea": 0x140001000, "site_op": 1, "value_adjust": 0,
    }

    def test_single_site_becomes_a_one_element_list(self):
        decl = declare.from_dict(dict(self.V1))
        self.assertEqual(decl.sites, [(0x140001000, 1)])
        self.assertEqual(decl.version, declare.DECL_VERSION)

    def test_v1_keeps_scanning(self):
        """It never asked for sites-only, so narrowing it would be a change."""
        decl = declare.from_dict(dict(self.V1))
        self.assertTrue(decl.scan_allowed)

    def test_v1_without_a_site_still_loads(self):
        data = dict(self.V1, site_ea=None, site_op=None)
        decl = declare.from_dict(data)
        self.assertEqual(decl.sites, [])
        self.assertTrue(decl.scan_allowed)

    def test_v1_sentinel_site_is_still_normalized(self):
        data = dict(self.V1, site_ea=0xFFFFFFFFFFFFFFFF, site_op=-1)
        self.assertEqual(declare.from_dict(data).sites, [])


class StrideTests(unittest.TestCase):
    """A stride asserts its value, so the rules around it are stricter."""

    def test_a_stride_needs_sites(self):
        """Nothing in the database can discover one, so none means none."""
        with self.assertRaises(declare.DeclarationError):
            declare.make_stride("CMeshDrawPrimitive", "kStride", 0x30, [])

    def test_a_stride_needs_a_value(self):
        with self.assertRaises(declare.DeclarationError):
            declare.Declaration(
                cfs6.SEM_ELEMENT_STRIDE, "T", "kStride", sites=[(0x1000, 1)]
            )

    def test_a_member_may_not_assert_a_value(self):
        """The offset is the database's answer, never the caller's."""
        with self.assertRaises(declare.DeclarationError):
            declare.Declaration(
                cfs6.SEM_MEMBER_OFFSET, "T", "f", sites=[(0x1000, 1)],
                asserted_value=0x30,
            )

    def test_a_stride_never_scans(self):
        decl = declare.make_stride("T", "kStride", 0x30, [(0x1000, 1)])
        self.assertFalse(decl.scan_allowed)
        self.assertFalse(decl.needs_ida_member)

    def test_stride_id_is_distinct_from_a_member_of_the_same_name(self):
        stride = declare.make_stride("T", "n", 4, [(0x1000, 1)])
        member = declare.make_member("T", "n")
        self.assertNotEqual(stride.id, member.id)
        self.assertTrue(stride.id.startswith("stride:"))

    def test_round_trip_keeps_the_asserted_value(self):
        decl = declare.make_stride("T", "kStride", 0x30, [(0x1000, 1)])
        again = declare.from_dict(decl.to_dict())
        self.assertEqual(again.asserted_value, 0x30)
        self.assertEqual(again.semantic, cfs6.SEM_ELEMENT_STRIDE)
        self.assertFalse(again.scan_allowed)


class StrideFileTests(unittest.TestCase):
    """A stride must survive the actual file, not just the model.

    `element_stride` was a reserved semantic that nothing ever emitted, so
    this is the check that the reader really does accept one -- the claim that
    no schema revision is needed rests on it.
    """

    def _write(self, path):
        cand = value_candidate(
            " ".join(["48"] * 6 + ["?"] + ["90"] * 5),
            op=cfs6.OP_IMM, value=0x30,
            origin=cfs6.ORIGIN_SELECTED_OPERAND,
        )
        with open(path, "w", encoding="utf-8", newline="") as handle:
            writer = cfs6.Cfs6Writer(handle)
            writer.write_header(sample_image(), 14182, "user")
            iid = writer.write_derived_value(
                cfs6.SEM_ELEMENT_STRIDE, "CMeshDrawPrimitive", "kStride",
                1, {}, expected_value=0x30,
            )
            writer.write_candidate(iid, 0, cand)
        return iid

    def test_a_stride_item_round_trips_through_the_reader(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "stride.cfs")
            iid = self._write(path)
            loaded = cfs6.load_cfs6(path)

            self.assertEqual(loaded.parse_errors, 0)
            self.assertEqual(loaded.skipped_records, 0)
            strides = loaded.derived_values(cfs6.SEM_ELEMENT_STRIDE)
            self.assertEqual(len(strides), 1)
            item = strides[0]
            self.assertEqual(item.id, iid)
            self.assertEqual(item.id, "stride:CMeshDrawPrimitive::kStride")
            self.assertEqual(item.kind, cfs6.REC_DERIVED_VALUE)
            self.assertEqual(item.expected_value, 0x30)
            self.assertEqual(item.qualified_name, "CMeshDrawPrimitive::kStride")

    def test_a_stride_does_not_answer_a_member_offset_query(self):
        """The semantic is a real discriminator, not a label."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "stride.cfs")
            self._write(path)
            loaded = cfs6.load_cfs6(path)
            self.assertEqual(loaded.derived_values(cfs6.SEM_MEMBER_OFFSET), [])

    def test_the_candidate_keeps_its_immediate_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "stride.cfs")
            self._write(path)
            loaded = cfs6.load_cfs6(path)
            item = loaded.derived_values(cfs6.SEM_ELEMENT_STRIDE)[0]
            self.assertEqual(len(item.candidates), 1)
            cand = item.candidates[0]
            # The extraction recipe travels as `resolve` -- it *is* how the
            # consumer resolves a VALUE, not metadata attached beside it.
            self.assertEqual(cand.resolve["op"], cfs6.OP_IMM)
            self.assertEqual(cand.mode, "VALUE")
            self.assertEqual(cand.origin, cfs6.ORIGIN_SELECTED_OPERAND)


# ---------------------------------------------------------------------------
# Resolution (the reference implementation)
# ---------------------------------------------------------------------------

class _FakeImage:
    """Just enough of PeImage to drive resolution: one flat executable blob."""

    def __init__(self, base_rva, data):
        self.base_rva = base_rva
        self.data = data

    def read(self, rva, size):
        offset = rva - self.base_rva
        if offset < 0 or offset + size > len(self.data):
            return None
        return self.data[offset:offset + size]

    def offset_to_rva(self, offset):
        return self.base_rva + offset

    def is_executable_rva(self, rva):
        return self.base_rva <= rva < self.base_rva + len(self.data)


def _resolve(cand_resolve, image_bytes, base_rva=0x1000, match_rva=0x1000,
             pattern="48 8B 8B ? ? ? ? 48 85 C9"):
    record = cfs6.CandidateRecord(
        line_no=1, item="member:T::f", rank=0, mode="VALUE",
        pattern=pattern, origin=cfs6.ORIGIN_STROFF_XREF,
        resolve=cand_resolve,
    )
    return cfs6_resolve.resolve_value(
        _FakeImage(base_rva, image_bytes), record, match_rva
    )


class ResolveValueTests(unittest.TestCase):
    BASE = {"op": "DISP", "instruction_offset": 0, "field_offset": 3,
            "field_size": 4, "operand_index": 1, "signed": True}

    def test_disp32_is_read_little_endian(self):
        data = bytes([0x48, 0x8B, 0x8B, 0xE0, 0x01, 0x00, 0x00])
        value, error = _resolve(self.BASE, data)
        self.assertIsNone(error)
        self.assertEqual(value, 0x1E0)

    def test_disp8_is_read_signed(self):
        # A subobject-relative access is legitimately negative.
        data = bytes([0x44, 0x8B, 0x43, 0xF8])
        value, error = _resolve(
            dict(self.BASE, field_size=1), data, pattern="44 8B 43 ?"
        )
        self.assertIsNone(error)
        self.assertEqual(value, -8)

    def test_value_adjust_shifts_the_answer(self):
        data = bytes([0x48, 0x8B, 0x8B, 0x10, 0x00, 0x00, 0x00])
        value, _ = _resolve(dict(self.BASE, value_adjust=0x20), data)
        self.assertEqual(value, 0x30)

    def test_const_needs_no_image_bytes(self):
        value, error = _resolve(
            {"op": "CONST", "instruction_offset": 0, "value": 0}, b""
        )
        self.assertIsNone(error)
        self.assertEqual(value, 0)

    def test_imm32_resolves(self):
        # `add rax, 0x30` -- how a stride is normally encoded.
        data = bytes([0x48, 0x83, 0xC0, 0x30])
        value, error = _resolve(
            {"op": "IMM", "instruction_offset": 0, "field_offset": 3,
             "field_size": 1, "operand_index": 1, "signed": False},
            data, pattern="48 83 C0 ?",
        )
        self.assertIsNone(error)
        self.assertEqual(value, 0x30)

    def test_an_unsigned_immediate_is_not_read_as_negative(self):
        """0x80 as a stride is 128, never -128.

        This is why `signed` is per candidate rather than per op: a
        displacement must be signed and a magnitude must not be.
        """
        data = bytes([0x48, 0x83, 0xC0, 0x80])
        value, _ = _resolve(
            {"op": "IMM", "instruction_offset": 0, "field_offset": 3,
             "field_size": 1, "operand_index": 1, "signed": False},
            data, pattern="48 83 C0 ?",
        )
        self.assertEqual(value, 128)

    def test_a_signed_immediate_still_reads_signed_when_asked(self):
        data = bytes([0x48, 0x83, 0xC0, 0x80])
        value, _ = _resolve(
            {"op": "IMM", "instruction_offset": 0, "field_offset": 3,
             "field_size": 1, "operand_index": 1, "signed": True},
            data, pattern="48 83 C0 ?",
        )
        self.assertEqual(value, -128)

    def test_an_unknown_op_is_refused_rather_than_guessed(self):
        value, error = _resolve(
            dict(self.BASE, op="SCALE"),
            bytes([0x48, 0x8B, 0x8B, 0x10, 0x00, 0x00, 0x00]),
        )
        self.assertIsNone(value)
        self.assertIn("unsupported extraction op", error)

    def test_disp_plus_width_adds_the_access_width(self):
        data = bytes([0x48, 0x8B, 0x8B, 0x10, 0x00, 0x00, 0x00])
        value, _ = _resolve(
            dict(self.BASE, op="DISP_PLUS_WIDTH", access_width=8), data
        )
        self.assertEqual(value, 0x18)

    def test_alignment_rounds_up(self):
        data = bytes([0x48, 0x8B, 0x8B, 0x11, 0x00, 0x00, 0x00])
        value, _ = _resolve(
            dict(self.BASE, op="DISP_PLUS_WIDTH", access_width=1, alignment=8),
            data,
        )
        self.assertEqual(value, 0x18)

    def test_unmapped_field_is_an_error_not_a_zero(self):
        value, error = _resolve(self.BASE, bytes([0x48, 0x8B]))
        self.assertIsNone(value)
        self.assertIn("not mapped", error)

    def test_field_before_the_instruction_is_refused(self):
        value, error = _resolve(
            dict(self.BASE, instruction_offset=5),
            bytes([0x48, 0x8B, 0x8B, 0xE0, 0x01, 0x00, 0x00]),
        )
        self.assertIsNone(value)
        self.assertIn("before its own instruction", error)

    def test_unsupported_op_is_refused(self):
        value, error = _resolve(
            dict(self.BASE, op="SCALE"),
            bytes([0x48, 0x8B, 0x8B, 0xE0, 0x01, 0x00, 0x00]),
        )
        self.assertIsNone(value)
        self.assertIn("unsupported extraction op", error)


class ResolveItemAgreementTests(_TempFileCase):
    """Agreement between independent sites is what confirms a value.

    For an address item, agreement means two patterns hit the same RVA. For a
    member it means two *unrelated instructions* encode the same number, which
    is why the candidates below sit in different parts of the fake image.
    """

    PATTERN_A = "48 8B 8B ? ? ? ? 48 85 C9"
    PATTERN_B = "4C 8B B3 ? ? ? ? 4D 85 F6"

    def _image(self, disp_a, disp_b):
        blob = bytearray()
        blob += bytes([0x48, 0x8B, 0x8B]) + disp_a.to_bytes(4, "little")
        blob += bytes([0x48, 0x85, 0xC9])
        blob += b"\xCC" * 16
        blob += bytes([0x4C, 0x8B, 0xB3]) + disp_b.to_bytes(4, "little")
        blob += bytes([0x4D, 0x85, 0xF6])
        return _FakeImage(0x1000, bytes(blob))

    def _item(self, expected=0x1E0):
        write_member_cfs6(self.path(), [(
            "T", "f", expected,
            [value_candidate(self.PATTERN_A, anchor=0x1000, value=expected),
             value_candidate(self.PATTERN_B, anchor=0x2000, value=expected)],
        )])
        return cfs6.load_cfs6(self.path()).derived_values()[0]

    def test_two_sites_encoding_the_same_number_confirm_each_other(self):
        value, status, details = cfs6_resolve.resolve_item(
            self._image(0x1E0, 0x1E0), self._item()
        )
        self.assertEqual(status, "ok")
        self.assertEqual(value, 0x1E0)
        self.assertEqual(sum(1 for d in details if "->" in d), 2)

    def test_two_sites_encoding_different_numbers_are_a_conflict(self):
        value, status, _ = cfs6_resolve.resolve_item(
            self._image(0x1E0, 0x1E8), self._item()
        )
        self.assertEqual(status, "conflict")
        self.assertIsNone(value)

    def test_a_moved_field_resolves_and_reports_as_drift(self):
        # Both sites agree on the new offset, so resolution succeeds; the
        # mismatch against expected_value is information, not an error.
        item = self._item(expected=0x1E0)
        value, status, _ = cfs6_resolve.resolve_item(
            self._image(0x1F0, 0x1F0), item
        )
        self.assertEqual(status, "ok")
        self.assertEqual(value, 0x1F0)
        self.assertNotEqual(value, item.expected_value)

    def test_a_pattern_that_does_not_match_never_resolves(self):
        item = self._item()
        value, status, _ = cfs6_resolve.resolve_item(
            _FakeImage(0x1000, b"\x90" * 64), item
        )
        self.assertEqual(status, "unresolved")
        self.assertIsNone(value)


if __name__ == "__main__":
    unittest.main()
