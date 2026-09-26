"""CFS7 structural refresh routing without opening an IDB."""

import sys
import unittest
from types import SimpleNamespace
from unittest import mock

import _support  # noqa: F401
from check import _StubFinder

sys.meta_path.insert(0, _StubFinder())

from cfs5 import cfs6, promotion, rolling  # noqa: E402


class TestStructuralRefreshValidation(unittest.TestCase):
    def setUp(self):
        self.target = 0x840CE0
        self.imagebase = 0x100000
        self.func = SimpleNamespace(start_ea=self.target, end_ea=self.target + 0x6D)
        self.confirm = SimpleNamespace(
            scan_range_for=lambda _target, _ownership: (
                self.target, self.target + 0x6D, cfs6.SCAN_BOUND_PDATA_CHAIN,
            ),
            verify_confirm_signature=lambda _pattern, _target, _ownership: True,
        )
        self.funcs = SimpleNamespace(get_func=lambda _ea: self.func)
        self.item = cfs6.ItemRecord(1, cfs6.REC_FUNCTION, "fn:locator", "locator")

    def _record(self, mode, resolve):
        return cfs6.CandidateRecord(
            2, self.item.id, 0, mode, "90 90", origin=(
                cfs6.ORIGIN_RTTI_VTABLE_SLOT if mode == cfs6.MODE_VTABLE
                else cfs6.ORIGIN_ANCHOR_STRING
            ),
            source={}, resolve=resolve,
        )

    def test_vtable_uses_structural_resolution_not_image_wide_pattern(self):
        rec = self._record(cfs6.MODE_VTABLE, {
            "type_descriptor": ".?AVCCSPlayerInventory@@",
            "subobject_offset": 0, "slot": 19, "confirm_offset": 0x58,
            "scan_bound": cfs6.SCAN_BOUND_PDATA_CHAIN,
        })
        rtti = SimpleNamespace(
            find_vtable=lambda _name, _subobject: object(),
            read_slot=lambda _table, _slot: (self.target, 0x1C04088),
        )
        with mock.patch.object(promotion, "rtti", rtti), \
             mock.patch.object(promotion, "confirm", self.confirm), \
             mock.patch.object(promotion, "ida_funcs", self.funcs), \
             mock.patch.object(promotion, "_unique_match", side_effect=AssertionError):
            result, error = promotion._validate(
                self.item, rec, [], self.imagebase, ownership=object(),
            )
        self.assertIsNone(error)
        self.assertEqual(result[2], self.target)
        self.assertEqual(result[1]["anchor_rva"], self.target + 0x58 - self.imagebase)

    def test_string_locator_uses_handler_then_bounded_confirmation(self):
        rec = self._record(cfs6.MODE_STRING_REL, {
            "string": "ShowGenericPopupOk", "confirm_offset": 0x1C,
            "scan_bound": cfs6.SCAN_BOUND_PDATA_CHAIN,
        })
        strloc = SimpleNamespace(resolve_anchor_string=lambda _text, _owner: {
            "function_ea": self.target,
        })
        with mock.patch.object(promotion, "strloc", strloc), \
             mock.patch.object(promotion, "confirm", self.confirm), \
             mock.patch.object(promotion, "ida_funcs", self.funcs), \
             mock.patch.object(promotion, "_unique_match", side_effect=AssertionError):
            result, error = promotion._validate(
                self.item, rec, [], self.imagebase, ownership=object(),
            )
        self.assertIsNone(error)
        self.assertEqual(result[2], self.target)


class TestRefreshCounts(unittest.TestCase):
    def test_only_emitted_active_items_count_as_added(self):
        source = [
            SimpleNamespace(id="fn:old"),
            SimpleNamespace(id="fn:retained"),
        ]
        self.assertEqual(
            rolling._active_counts(source, {"fn:new"}),
            {"added": 1, "refreshed": 0},
        )
        self.assertEqual(
            rolling._active_counts(source, set()),
            {"added": 0, "refreshed": 0},
        )
        self.assertEqual(
            rolling._active_counts(source, {"fn:old"}),
            {"added": 0, "refreshed": 1},
        )
