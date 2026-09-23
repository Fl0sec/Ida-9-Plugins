# Signature durability across builds — measured, and what not to retry

Measured on cs2 `client.dll` 14181 → 14182: export from 14181, scan 14182's
`.text` for every candidate pattern.

```
1833 candidates   1501 unique (82%)   296 zero-match   36 ambiguous (2+)
 627 items         581 keep >=1 candidate              46 lost outright
```

**~16% per-candidate attrition across one build bump is normal.** The format is
built for it: multiple independent candidates per item, and re-export per
build. Do not read a lost item as a bug without measuring first.

## Two fixes that look obvious and are not

Both were implemented, measured against the real builds, and reverted. Do not
re-propose them without new evidence.

| Attempt | Recovered | Regressed | Net |
|---|---|---|---|
| Wildcard `disp32` member offsets in REL neighbour instructions | 14 | 44 | **−30** |
| Add forward-only windows `(xidx, xidx+3)` / `(xidx, xidx+4)` | 5 | 18 | **−13** |

Why each fails:

- **Wildcarding the offset** costs 4 exact bytes. It revives patterns broken by
  a layout shift, but pushes more short patterns into ambiguity than it saves.
- **Adding shorter window options** makes `_unique_window_around` — which keeps
  the *shortest* source-unique window — pick a less discriminating pattern.
  Within one anchor, shorter is strictly weaker.

## The measurement traps that produced those two wrong answers

Both came from counting only the upside:

- Counting patterns a change *revives* without counting patterns it *breaks*.
  The first attempt looked like "+55" under that error; it is −30.
- Measuring that a durable window **exists** rather than that the selector
  would **choose** it. The second looked like "+24"; it is −13.

Any future proposal must report both directions, from a re-export, on a real
build pair.

## Facts to build on

- **A zero-match pattern cannot be revived by lengthening it.** Only
  wildcarding (measured, net-negative) or picking a *different anchor site*
  can help. That rules out most of the obvious ideas for the 296.
- Pattern length barely correlates with survival: 83.8% at ≤10 bytes, 78.8% at
  ≤48. `policy.Candidate.score`'s length bias is not doing harm, and not doing
  much good either.
- The dominant failure is a struct layout shift: a C++ field insertion moves
  every member after it, so a pinned `disp32` in the window breaks a pattern
  whose instruction stream is otherwise byte-identical. Worked example —
  `g_p_planted_c4_list_head`, anchor `0xC59958`, where only `0x1188 → 0x1270`
  changed.
- The 36 ambiguous candidates are a *separate* bucket and are the one group
  that lengthening can fix. Unmeasured.

## Untried, and the only direction still worth it

Prefer, among windows that are **equally source-unique**, one containing no
volatile `disp32` — a tie-break in selection rather than a wildcard. It never
removes exact bytes, so it cannot cause the first attempt's regression.

It cannot be evaluated offline: reconstructing the backward instruction
boundaries needs IDA, so it requires a re-export from 14181 and a re-scan.
