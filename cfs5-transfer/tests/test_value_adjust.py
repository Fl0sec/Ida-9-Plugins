"""The `value_adjust` convention, in both directions.

`value_adjust` was unusable for any non-zero value: the exporter searched the
evidence site for the number it was going to *export*, when a site with an
adjustment by definition encodes something else. Every such declaration was
refused for "no candidate", which reads as "your site is wrong" and is not.

The bug is invisible to any test using an adjustment of `0`, where all three
numbers coincide -- which is why every test here uses a non-zero one, in both
directions, and why the zero case is pinned separately as the thing that must
not change.

The three cases below are the real declarations this blocked, with their
verified site evidence from cs2 `client.dll` build 14182.
"""

import unittest

from cfs5 import declare


# (member, site adjustment, what the site encodes, what must be exported)
REAL_CASES = (
    ("BulletPenContext::m_nRecordsCap", 8, 0x8, 0x10),
    ("BulletPenContext::m_nEventsCap", 8, 0x1C28, 0x1C30),
    ("CSGOUserCmdPB::m_pBaseCmd", -0x10, 0x40, 0x30),
)


def _member(value_adjust):
    return declare.make_member(
        "T", "f", sites=[{"ea": 0x140001000, "op": 1}],
        value_adjust=value_adjust,
    )


class ValueAdjustDirectionTests(unittest.TestCase):
    def test_site_value_is_the_reported_value_minus_the_adjustment(self):
        """The exporter's direction: it knows the answer, needs the search key.

        This is the assertion the defect failed. The exporter learns `0x10`
        from IDA and has to look for `0x8` at the site; looking for `0x10`
        finds nothing, because nothing there encodes it.
        """
        for name, adjust, encoded, reported in REAL_CASES:
            with self.subTest(member=name):
                self.assertEqual(_member(adjust).site_value(reported), encoded)

    def test_reported_value_is_the_site_value_plus_the_adjustment(self):
        """The consumer's direction, which is what the file's contract says."""
        for name, adjust, encoded, reported in REAL_CASES:
            with self.subTest(member=name):
                self.assertEqual(_member(adjust).reported_value(encoded),
                                 reported)

    def test_the_two_directions_are_inverses(self):
        """Neither side may apply the adjustment twice, or at all, alone.

        Applying it on both sides -- the shape of the original defect -- makes
        this round trip land `2 * value_adjust` away from where it started, for
        every adjustment except zero.
        """
        for adjust in (-0x40, -0x10, -1, 0, 1, 8, 0x1000):
            decl = _member(adjust)
            for reported in (0x0, 0x8, 0x30, 0x1C30):
                with self.subTest(adjust=adjust, reported=reported):
                    self.assertEqual(
                        decl.reported_value(decl.site_value(reported)),
                        reported,
                    )

    def test_a_sign_flip_does_not_satisfy_the_round_trip(self):
        """Guards against "fixing" the direction by negating the adjustment.

        Negating moves the failure instead of removing it, which is what the
        original report observed when it tried the opposite sign.
        """
        decl = _member(8)
        self.assertNotEqual(decl.reported_value(decl.site_value(0x10) - 16),
                            0x10)
        self.assertEqual(decl.site_value(0x10), 0x8)
        self.assertNotEqual(decl.site_value(0x10), 0x18)

    def test_zero_adjust_collapses_all_three_numbers(self):
        """Why this survived: every existing declaration uses 0.

        With no adjustment the site value and the reported value are the same
        number, so old and new arithmetic agree by construction and no already
        declared member changes behaviour.
        """
        decl = _member(0)
        for value in (0x0, 0x8, 0x610, 0x2120):
            self.assertEqual(decl.site_value(value), value)
            self.assertEqual(decl.reported_value(value), value)


class AssertedValueAdjustTests(unittest.TestCase):
    """The same convention on a semantic with no IDA field behind it."""

    def test_a_stride_site_value_is_relative_to_the_asserted_value(self):
        decl = declare.make_stride(
            "T", "kStride", 0x30, [{"ea": 0x140001000, "op": 1}],
            value_adjust=-0x10,
        )
        self.assertEqual(decl.asserted_value, 0x30)
        self.assertEqual(decl.site_value(decl.asserted_value), 0x40)
        self.assertEqual(decl.reported_value(0x40), 0x30)

    def test_a_constant_uses_the_same_convention(self):
        decl = declare.make_constant(
            "SosConstants", "kDisableStartTime", 0xFF,
            [{"ea": 0x140001000, "op": 1}], value_adjust=1,
        )
        self.assertEqual(decl.site_value(decl.asserted_value), 0xFE)
        self.assertEqual(decl.reported_value(0xFE), 0xFF)


class RoundTripTests(unittest.TestCase):
    def test_value_adjust_survives_storage(self):
        """A stored declaration must not lose the sign of its adjustment."""
        for adjust in (-0x10, 0, 8):
            decl = _member(adjust)
            back = declare.from_dict(decl.to_dict())
            with self.subTest(adjust=adjust):
                self.assertEqual(back.value_adjust, adjust)
                self.assertEqual(back.site_value(0x10), decl.site_value(0x10))


if __name__ == "__main__":
    unittest.main()
