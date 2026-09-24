"""The export set's identity rules (cfs5/registry.py)."""

import unittest

import _support  # noqa: F401  (puts the plugin dir on sys.path)

from cfs5 import cfs6, registry


class TestEntryId(unittest.TestCase):
    def test_ids_share_the_cfs6_item_namespace(self):
        """A registry entry and the record it produces are the same string."""
        self.assertEqual(
            registry.entry_id(registry.KIND_FUNCTION, "Foo"),
            cfs6.item_id(cfs6.REC_FUNCTION, "Foo"),
        )
        self.assertEqual(
            registry.entry_id(registry.KIND_GLOBAL, "g_x"),
            cfs6.item_id(cfs6.REC_GLOBAL, "g_x"),
        )

    def test_unknown_kind_is_refused(self):
        with self.assertRaises(registry.RegistryError):
            registry.entry_id("member", "Foo")

    def test_non_identifier_names_are_refused(self):
        for bad in ("", "has space", "?mangled@@", "std::vector", "1st", None):
            with self.assertRaises(registry.RegistryError):
                registry.entry_id(registry.KIND_FUNCTION, bad)

    def test_round_trip(self):
        for kind, name in (
            (registry.KIND_FUNCTION, "CBaseEntity_Spawn"),
            (registry.KIND_GLOBAL, "g_pEntityList"),
        ):
            iid = registry.entry_id(kind, name)
            self.assertEqual(registry.parse_entry_id(iid), (kind, name))

    def test_parse_rejects_junk(self):
        for bad in ("junk", "fn:", "", 42, None):
            with self.assertRaises(registry.RegistryError):
                registry.parse_entry_id(bad)


class TestNormalize(unittest.TestCase):
    def test_vtable_locator_normalizes_and_rejects_bad_shapes(self):
        ids, _sites, locators, rejected = registry.normalize_entries(
            registry.KIND_FUNCTION,
            [{"name": "notify", "vtable": {"type": "C", "slot": 19}}],
        )
        self.assertEqual(ids, ["fn:notify"])
        self.assertEqual(locators["fn:notify"][0], {
            "kind": "vtable", "type": "C", "slot": 19,
            "subobject_offset": None,
        })
        self.assertEqual(rejected, [])

        for spec in ({"type": "", "slot": 1}, {"type": "C"},
                     {"type": "C", "slot": -1}):
            _ids, _sites, _locators, rejected = registry.normalize_entries(
                registry.KIND_FUNCTION, [{"name": "notify", "vtable": spec}]
            )
            self.assertEqual(len(rejected), 1)

    def test_a_bad_name_does_not_lose_the_batch(self):
        """Fifty names with two typos must register forty-eight."""
        names = ["Good%d" % i for i in range(48)] + ["bad name", "?x@@"]
        ids, rejected = registry.normalize(registry.KIND_FUNCTION, names)
        self.assertEqual(len(ids), 48)
        self.assertEqual(len(rejected), 2)
        for entry in rejected:
            self.assertIn("reason", entry)
            self.assertTrue(entry["reason"])

    def test_deduplicates_and_keeps_order(self):
        ids, _ = registry.normalize(
            registry.KIND_FUNCTION, ["B", "A", "B", "C", "A"]
        )
        self.assertEqual(ids, ["fn:B", "fn:A", "fn:C"])

    def test_empty_input_is_not_an_error(self):
        self.assertEqual(registry.normalize(registry.KIND_GLOBAL, []), ([], []))
        self.assertEqual(registry.normalize(registry.KIND_GLOBAL, None), ([], []))


class TestEntriesWithSites(unittest.TestCase):
    """An entry may carry anchor sites the caller located itself."""

    def test_a_plain_name_still_works_and_carries_no_sites(self):
        ids, sites, _locators, rejected = registry.normalize_entries(
            registry.KIND_FUNCTION, ["Alpha"]
        )
        self.assertEqual(ids, ["fn:Alpha"])
        self.assertEqual(sites, {})
        self.assertEqual(rejected, [])

    def test_sites_are_collected_against_the_entry_id(self):
        ids, sites, _locators, _ = registry.normalize_entries(
            registry.KIND_FUNCTION,
            [{"name": "Alpha", "sites": [0x1000, {"ea": 0x2000}]}],
        )
        self.assertEqual(ids, ["fn:Alpha"])
        self.assertEqual(sites, {"fn:Alpha": [0x1000, 0x2000]})

    def test_repeating_a_name_merges_its_sites(self):
        # Finding a second anchor must not mean repeating the first.
        _ids, sites, _locators, _ = registry.normalize_entries(
            registry.KIND_FUNCTION,
            [{"name": "Alpha", "sites": [0x1000]},
             {"name": "Alpha", "sites": [0x2000, 0x1000]}],
        )
        self.assertEqual(sites, {"fn:Alpha": [0x1000, 0x2000]})

    def test_sentinels_are_dropped_not_stored(self):
        # BADADDR and 0 are how "no address" arrives from IDA; storing one
        # would produce a confusing decode failure much later.
        self.assertEqual(
            registry.normalize_sites([0, 0xFFFFFFFFFFFFFFFF, 0x1234]), [0x1234]
        )

    def test_a_site_that_is_not_an_address_is_refused(self):
        with self.assertRaises(registry.RegistryError):
            registry.normalize_sites(["not-an-address"])

    def test_a_bad_entry_does_not_lose_the_batch(self):
        ids, sites, _locators, rejected = registry.normalize_entries(
            registry.KIND_FUNCTION,
            [{"name": "Good", "sites": [0x1000]},
             {"name": "bad name"},
             {"name": "AlsoGood"}],
        )
        self.assertEqual(ids, ["fn:Good", "fn:AlsoGood"])
        self.assertEqual(sites, {"fn:Good": [0x1000]})
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["name"], "bad name")

    def test_normalize_still_returns_two_values(self):
        # The old shape has three call sites in api.py; it must not change.
        self.assertEqual(
            registry.normalize(registry.KIND_FUNCTION, ["Alpha"]),
            (["fn:Alpha"], []),
        )


class TestSplitByKind(unittest.TestCase):
    def test_groups_and_sorts(self):
        out = registry.split_by_kind(
            ["fn:Zeta", "fn:Alpha", "global:g_b", "global:g_a"]
        )
        self.assertEqual(out[registry.KIND_FUNCTION], ["Alpha", "Zeta"])
        self.assertEqual(out[registry.KIND_GLOBAL], ["g_a", "g_b"])

    def test_unparseable_entries_are_skipped_not_fatal(self):
        """A netnode written by a newer plugin must not break listing."""
        out = registry.split_by_kind(["fn:Ok", "future:thing", "", None, 7])
        self.assertEqual(out[registry.KIND_FUNCTION], ["Ok"])
        self.assertEqual(out[registry.KIND_GLOBAL], [])

    def test_always_returns_every_kind(self):
        out = registry.split_by_kind([])
        self.assertEqual(sorted(out), sorted(registry.VALID_KINDS))


class TestOutcome(unittest.TestCase):
    """What `ok` means. The rule the whole API contract rests on."""

    def test_everything_succeeded(self):
        self.assertEqual(registry.outcome(52, 52, []), (True, False))

    def test_partial_success_is_never_ok(self):
        """51 of 52 must not read as success."""
        ok, partial = registry.outcome(52, 51, [{"name": "x"}])
        self.assertFalse(ok)
        self.assertTrue(partial)

    def test_missed_items_defeat_ok_even_at_full_count(self):
        """A count that adds up but carries a reported miss is still not ok."""
        ok, partial = registry.outcome(10, 10, [{"name": "renamed"}])
        self.assertFalse(ok)
        self.assertTrue(partial)

    def test_total_failure_is_neither_ok_nor_partial(self):
        ok, partial = registry.outcome(5, 0, [{"name": "a"}])
        self.assertFalse(ok)
        self.assertFalse(partial)

    def test_empty_batch_is_ok(self):
        self.assertEqual(registry.outcome(0, 0, []), (True, False))

    def test_none_missed_is_treated_as_empty(self):
        self.assertEqual(registry.outcome(3, 3, None), (True, False))

    def test_ok_and_partial_are_never_both_true(self):
        for asked in range(0, 6):
            for done in range(0, asked + 1):
                for missed in ([], [{"name": "x"}]):
                    ok, partial = registry.outcome(asked, done, missed)
                    self.assertFalse(ok and partial)


if __name__ == "__main__":
    unittest.main()
