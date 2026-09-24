"""Window growth around an anchor instruction, bounded in bytes not in count.

The VALUE path once grew its window along a fixed ladder of instruction
counts reaching three instructions back. That is the wrong bound when the
anchor is short: a `bt reg, imm8` is 4 bytes and a `shr reg, imm8` is 3, so the
ladder exhausted itself around 11 bytes and refused two constants whose unique
windows were 15 and 20 bytes away -- *inside the same function*, needing no
boundary crossing.

The sequence below is the real one from cs2 `client.dll` build 14182,
`Entity_IsClientModelChangeAllowed` at `0x15D8A60`:

    0x15D8A75  84 C0              test al, al
    0x15D8A77  75 ??              jnz short ...
    0x15D8A79  48 8B 4B 10        mov rcx, [rbx+10h]
    0x15D8A7D  8B 41 30           mov eax, [rcx+30h]
    0x15D8A80  0F BA E0 0B        bt eax, 0Bh        <- site, value 0xB
    0x15D8A84  73 ??              jnb short ...
    0x15D8A86  C1 E8 06           shr eax, 6         <- site, value 0x6

A test that uses a longer anchor instruction passes against the old ladder and
does not cover this, which is why these two anchors are 4 and 3 bytes.
"""

import unittest

from cfs5.policy import (
    MAX_PATTERN_BYTES, MAX_UNIQUE_PROBES, anchored_window_specs,
)


# (ea, size) exactly as `disasm.decode_chunk` reports them.
SEQUENCE = [
    (0x15D8A75, 2),   # 0 test al, al
    (0x15D8A77, 2),   # 1 jnz
    (0x15D8A79, 4),   # 2 mov rcx, [rbx+10h]
    (0x15D8A7D, 3),   # 3 mov eax, [rcx+30h]
    (0x15D8A80, 4),   # 4 bt eax, 0Bh          <- anchor for 0xB
    (0x15D8A84, 2),   # 5 jnb
    (0x15D8A86, 3),   # 6 shr eax, 6           <- anchor for 0x6
]

BT_IDX = 4
SHR_IDX = 6


def insns(pairs=SEQUENCE):
    return [{"ea": ea, "size": size, "tokens": ["??"] * size}
            for ea, size in pairs]


def span(items, spec):
    a, b = spec
    return items[b - 1]["ea"] + items[b - 1]["size"] - items[a]["ea"]


class AnchoredWindowGrowthTests(unittest.TestCase):
    def test_the_bt_site_reaches_its_15_byte_window(self):
        """4 instructions back from a 4-byte anchor, 0 forward.

        The refused case. The old ladder reached 3 back and never produced
        this window, so the site was reported as having no unique pattern when
        one was 15 bytes wide and entirely inside the function.
        """
        items = insns()
        specs = anchored_window_specs(items, BT_IDX)
        self.assertIn((0, BT_IDX + 1), specs)
        self.assertEqual(span(items, (0, BT_IDX + 1)), 15)

    def test_the_shr_site_reaches_its_20_byte_window(self):
        """6 instructions back from a 3-byte anchor, 0 forward."""
        items = insns()
        specs = anchored_window_specs(items, SHR_IDX)
        self.assertIn((0, SHR_IDX + 1), specs)
        self.assertEqual(span(items, (0, SHR_IDX + 1)), 20)

    def test_a_backwards_only_window_is_offered(self):
        """The window that pins these sites lies entirely behind them.

        A growth scheme that only extended forward, or only in balanced steps,
        would enumerate neither of the two windows above.
        """
        specs = anchored_window_specs(insns(), SHR_IDX)
        backwards_only = [(a, b) for a, b in specs if b == SHR_IDX + 1]
        self.assertGreater(len(backwards_only), 4)

    def test_every_window_contains_the_anchor(self):
        for xidx in range(len(SEQUENCE)):
            for a, b in anchored_window_specs(insns(), xidx):
                with self.subTest(anchor=xidx, window=(a, b)):
                    self.assertLessEqual(a, xidx)
                    self.assertLess(xidx, b)

    def test_shortest_first(self):
        """The first unique window found must be the smallest one."""
        items = insns()
        spans = [span(items, s) for s in anchored_window_specs(items, BT_IDX)]
        self.assertEqual(spans, sorted(spans))
        # The anchor alone is the smallest possible window.
        self.assertEqual(spans[0], 4)

    def test_growth_is_bounded_in_bytes(self):
        items = insns()
        for spec in anchored_window_specs(items, BT_IDX):
            self.assertLessEqual(span(items, spec), MAX_PATTERN_BYTES)

    def test_a_tighter_byte_budget_is_honoured(self):
        items = insns()
        specs = anchored_window_specs(items, BT_IDX, max_bytes=8)
        self.assertTrue(specs)
        for spec in specs:
            self.assertLessEqual(span(items, spec), 8)
        # ...and the 15-byte window is then correctly out of reach.
        self.assertNotIn((0, BT_IDX + 1), specs)

    def test_growth_never_leaves_the_instruction_list(self):
        """The caller passes the enclosing function chunk, so this is the clamp.

        A window may not reach into padding or a neighbouring function however
        far it grows, and that guarantee is structural rather than a check.
        """
        items = insns()
        for a, b in anchored_window_specs(items, BT_IDX):
            self.assertGreaterEqual(a, 0)
            self.assertLessEqual(b, len(items))

    def test_a_long_run_of_one_byte_instructions_stays_bounded(self):
        """The pathological shape for a byte bound: 60 single-byte instructions."""
        items = insns([(0x1000 + i, 1) for i in range(60)])
        specs = anchored_window_specs(items, 30)
        self.assertTrue(specs)
        for spec in specs:
            self.assertLessEqual(span(items, spec), MAX_PATTERN_BYTES)

    def test_an_out_of_range_anchor_yields_nothing(self):
        self.assertEqual(anchored_window_specs(insns(), 99), [])
        self.assertEqual(anchored_window_specs(insns(), -1), [])
        self.assertEqual(anchored_window_specs([], 0), [])


class ProbeBudgetTests(unittest.TestCase):
    """Enumerating a window is useless if the probe cap is reached first.

    Each uniqueness test is an image-wide byte search, so the number of them is
    capped. Ordering is shortest-first, so what matters is how many windows are
    *shorter* than the one that wins: that count is the number of probes spent
    before the answer, and it has to fit the budget in a realistically sized
    function, not just in the seven-instruction excerpt above.
    """

    # The reported sequence inside a ~103-byte function, which is what
    # Entity_IsClientModelChangeAllowed actually is.
    PADDING_BEFORE = [4, 3, 5, 2, 4, 3, 7, 4, 2, 3]
    PADDING_AFTER = [4, 3, 2, 5, 3, 4, 2, 6, 3, 4, 5, 3]

    def _padded(self):
        sizes = (self.PADDING_BEFORE
                 + [size for _ea, size in SEQUENCE]
                 + self.PADDING_AFTER)
        ea = 0x15D8A60
        pairs = []
        for size in sizes:
            pairs.append((ea, size))
            ea += size
        return insns(pairs), len(self.PADDING_BEFORE)

    def _probes_before(self, anchor_idx, target_bytes):
        items, offset = self._padded()
        idx = offset + anchor_idx
        spans = [span(items, s) for s in anchored_window_specs(items, idx)]
        self.assertIn(target_bytes, spans)
        return sum(1 for v in spans if v < target_bytes)

    def test_the_bt_window_is_reached_within_the_probe_budget(self):
        self.assertLess(self._probes_before(BT_IDX, 15), MAX_UNIQUE_PROBES)

    def test_the_shr_window_is_reached_within_the_probe_budget(self):
        self.assertLess(self._probes_before(SHR_IDX, 20), MAX_UNIQUE_PROBES)

    def test_the_budget_has_headroom_beyond_the_reported_cases(self):
        """Both fit with room to spare, so a slightly harder site still works."""
        worst = max(self._probes_before(BT_IDX, 15),
                    self._probes_before(SHR_IDX, 20))
        self.assertLess(worst * 2, MAX_UNIQUE_PROBES)


class OldLadderRegressionTests(unittest.TestCase):
    """Pins the specific reach that was missing, so it cannot regress quietly."""

    def test_the_new_bound_reaches_further_back_than_three_instructions(self):
        items = insns()
        specs = anchored_window_specs(items, SHR_IDX)
        deepest = min(a for a, _b in specs)
        self.assertEqual(deepest, 0)
        self.assertGreaterEqual(SHR_IDX - deepest, 6)


if __name__ == "__main__":
    unittest.main()
