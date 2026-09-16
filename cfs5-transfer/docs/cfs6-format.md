# The CFS6 format

**Authoritative specification.** This document defines the `.cfs` interchange
format. `cfs5/cfs6.py` is the reference writer/reader and `tools/cfs6_resolve.py`
is the reference *resolver*; where an implementation disagrees with them, they
are right.

CFS6 is designed to be consumed **without IDA**. Nothing required to resolve a
signature depends on IDA semantics.

---

## 1. Container

- **UTF-8, no BOM.** One JSON object per line, terminated by `\n`.
- Blank lines are ignored. There are no comment lines — use a record field.
- Every line is independently parseable, so errors are reported per line.
- The **first** non-empty line MUST be the `header` record. A file whose first
  line is not a valid CFS6 header MUST be rejected outright, not guessed at.
- Exactly one `header`, describing exactly one image, per file.
- Multiple `.cfs` files may live in one module directory; each is fully
  self-describing. **Filenames carry no meaning** — `f.cfs`, `g.cfs` and
  `all.cfs` are cosmetic, and a consumer must never infer content from them.

### Numbers

All offsets, sizes and RVAs are **JSON decimal integers**. Hex string forms are
not used. Offsets are **unsigned** unless stated otherwise; the only signed
quantity in the format is the displacement *read out of the image*, and
`target_delta`, which may be negative.

---

## 2. Record kinds

| `record` | Required | Purpose |
|---|---|---|
| `header` | yes, exactly one, first | format version + source image identity |
| `function` | — | a function item |
| `global` | — | a global-variable item |
| `candidate` | — | one signature candidate belonging to an item |
| `function_type` | optional | IDA `tinfo_t` prototype payload |
| `global_type` | optional | IDA `tinfo_t` type payload |
| `local_type` | optional | IDA `tinfo_t` named local type payload |

An **unknown `record` value must be reported and skipped**, not treated as an
error — that is the forward-compatibility hinge. **Unknown fields inside a known
record must be ignored.**

The three `*_type` records are IDA-specific and **independently skippable**.
Resolution never depends on decoding them. A dumper should ignore them entirely.

---

## 3. `header`

```json
{"record":"header","format":"CFS","version":6,"schema_revision":0,
 "generator":{"name":"cfs5-transfer","version":"6.0.0"},
 "image":{"name":"client.dll","format":"PE","architecture":"x86_64",
          "timestamp":1788412510,"size_of_image":41803776,"sha256":"…"},
 "build":{"number":14177,"source":"path-confirmed"},
 "scoring":{"direction":"lower-is-better"}}
```

| Field | Notes |
|---|---|
| `format` | always `"CFS"`. Any other value → not a CFS file. |
| `version` | **major**. `6`. A different value MUST be rejected. |
| `schema_revision` | additive revisions within v6. An **unknown value is fine** — parse anyway. |
| `image.*` | identity of the image the signatures were built from. Any field may be `null` when the exporter could not determine it. |
| `image.sha256` | hex digest of the whole input file, lower case. |
| `build.number` | integer, or **`null` when unknown — never `0`**. |
| `build.source` | `"path-confirmed"`, `"path-detected"`, `"user"`, or `"unknown"`. |
| `scoring.direction` | always `"lower-is-better"`. |

**The entire `image` block and `build` block are diagnostics.** They exist so a
human can tell where a file came from. A consumer MUST NOT use them to decide
whether to resolve, and MUST NOT treat a mismatch as a failure — applying a file
across builds is the intended use case.

---

## 4. `function` / `global` items

```json
{"record":"function","id":"fn:ConVarRef_GetFloat","name":"ConVarRef_GetFloat",
 "candidate_count":3,
 "coverage":{"entry":"selected","external_rel":"selected","body":"selected"}}
```

- `id` is unique within the file. Convention: `fn:<name>` and `global:<name>`.
  Candidates reference it via their `item` field. Treat it as an opaque key.
- `name` is the symbol name to apply.
- `candidate_count` is advisory; trust the candidates actually present.
- `coverage` reports, per axis, one of `selected`, `none_unique`,
  `not_applicable`. Diagnostic only. Axes: `entry`, `external_rel`, `body`, and
  `self_rel` when a self-referencing anchor had to be used.

Duplicate `id`, or a candidate naming an unknown `item`, is an error.

---

## 5. `candidate`

```json
{"record":"candidate","item":"fn:ConVarRef_GetFloat","rank":0,"mode":"REL",
 "pattern":"0F 28 F0 E8 ? ? ? ? 48 8B 6C 24 50","origin":"external_call",
 "score":1320,
 "source":{"function_rva":1470544,"function_size":156,"anchor_rva":1489927},
 "resolve":{"instruction_offset":3,"displacement_offset":4,
            "displacement_size":4,"base_offset":8}}
```

| Field | Meaning |
|---|---|
| `item` | the owning item's `id`. |
| `rank` | **authoritative** order. Contiguous from `0` within an item. |
| `mode` | `ENTRY`, `REL` or `BODY`. |
| `pattern` | space-separated uppercase hex bytes; `?` is a single-byte wildcard. |
| `origin` | provenance category (below). Diagnostic. |
| `score` | **lower is better**. Diagnostic ranking aid — **never** proof of identity. |
| `source` | historical RVAs. **Diagnostics only.** |
| `resolve` | the only fields used to resolve. Mode-specific. |

`origin` values: `function_entry`, `external_call`, `self_call`,
`data_reference`, `body_early`, `body_middle`, `body_late`.

### `resolve` fields

**Every offset in `resolve` is relative to the start of the pattern match.**

| Field | Modes | Meaning |
|---|---|---|
| `instruction_offset` | REL | offset of the anchor instruction's first byte |
| `displacement_offset` | REL | offset of the signed little-endian displacement field |
| `displacement_size` | REL | **1, 2, 4 or 8** — any other value is invalid |
| `base_offset` | REL | offset of the **end of the whole anchor instruction** |
| `ownership` | BODY | `"pdata"` or `"ida-only"` — see below |
| `target_delta` | all | **optional, default `0`**; signed; added to the resolved target |

### `source` fields

| Field | Present for | Meaning |
|---|---|---|
| `function_rva` | function candidates | source RVA of the owning function |
| `function_size` | function candidates | **diagnostic only — never a rejection reason** |
| `target_rva` | global candidates | source RVA of the global |
| `anchor_rva` | all | source RVA of the pattern-match start |
| `body_offset` | BODY | pattern start minus function start; `>= 0`; **resolution-critical** |

---

## 6. Resolution

Let `match` be the RVA where `pattern` matched. **A pattern that does not match
exactly once does not resolve.** Zero matches and two-or-more matches are both
hard failures. Never "take the first hit".

Restrict the search to executable sections.

### ENTRY

```
target = match + target_delta
```

### REL

```
insn_start = match + instruction_offset
insn_end   = match + base_offset
field      = match + displacement_offset

REQUIRE insn_start <= field  and  field + displacement_size <= insn_end

disp   = signed_le(image[field : field + displacement_size])
target = match + base_offset + disp + target_delta
```

A consumer SHOULD additionally decode the instruction at `insn_start` and
require that it ends exactly at `insn_end`, which detects an instruction whose
encoding changed under the same byte prefix.

> **`base_offset` is stored and MUST NOT be inferred.** It is the end of the
> *whole* instruction, trailing immediates included. Deriving the base from the
> displacement field's own end is correct for `call rel32` but **wrong** for
> forms like `mov [rip+disp32], imm32`, where immediate bytes sit between the
> field and the instruction end. This is the single most likely place two
> implementations silently diverge.

### BODY

**First check `resolve.ownership`.**

- `"pdata"` — resolvable by the algorithm below.
- `"ida-only"` — the exporter determined that this function's owner is **not**
  recoverable from `.pdata`: either the function start is not a
  `RUNTIME_FUNCTION` begin, or the function is chunked/outlined and the body
  anchor falls in a different `.pdata` range than its start. A non-IDA consumer
  **MUST skip such a candidate.** Skipping it is correct behaviour, not a file
  error — the candidate exists for IDA-to-IDA transfer, which uses IDA's own
  function ownership. In a real cs2 `client.dll` export this affects roughly 1%
  of functions.

Any unrecognised `ownership` value must also be skipped, not guessed at.

```
candidate_start = match - body_offset

REQUIRE candidate_start is the start of EXACTLY ONE .pdata RUNTIME_FUNCTION
REQUIRE match lies inside that runtime function's [begin, end) range

target = candidate_start + target_delta
```

Containment alone is **not** sufficient — `candidate_start` must land on a
range's `begin`. Never fall back to "the nearest preceding function". A body hit
that does not satisfy both conditions MUST NOT resolve.

`function_size` MUST NOT be used to reject a BODY hit; a function that grew by
one instruction is still the right function.

---

## 7. Multiple candidates, agreement and conflict

Candidates for one item are **independent evidence**, deliberately drawn from
different origins so that they fail for unrelated reasons.

A consumer MUST:

1. Evaluate **every** candidate, not just the first that succeeds.
2. If two or more candidates resolve to the **same** target → resolve to it, and
   treat the agreement as confirmation (worth surfacing in a summary).
3. If two or more candidates resolve to **different** targets → this is a
   **conflict**. Resolve to **nothing** and report loudly. Preferring `rank 0`
   here defeats the purpose of exporting diverse candidates.
4. If exactly one resolves → use it, and note the others' failure reasons.
5. If none resolve → unresolved.

Two *different* items resolving to the same address is also a conflict and
should be reported.

---

## 8. `function_type` / `global_type` / `local_type` (optional, IDA-specific)

```json
{"record":"function_type","item":"fn:Foo","name":"Foo","quality":"USER",
 "encoding":"zlib+base64","producer":"ida-9.0-tinfo",
 "type":"…","fields":"…","field_comments":"…","dependencies":"…"}
```

`type`, `fields`, `field_comments` are zlib-compressed, base64-encoded
serialized IDA `tinfo_t` payloads. `dependencies` is a zlib+base64 compressed
JSON array of local-type names. `quality` is `USER`, `EXPLICIT`, `GUESSED` or
`NONE`. `local_type` has `name`/`kind` instead of `item`.

Skip these unless you are an IDA-based consumer.

---

## 9. Validation checklist for a reader

Fatal (reject the file):
- first non-empty line is not a valid `header`
- `format != "CFS"` or `version != 6`
- `header` has no `image` object

Recoverable (count, report with the line number, skip the record):
- malformed JSON on a line; a line that is not a JSON object
- duplicate `id`; duplicate `(item, rank)`; non-contiguous ranks within an item
- candidate referencing an unknown `item`
- unsupported `mode`; empty `pattern`
- REL: `displacement_size` not in {1,2,4,8}; negative offsets; `base_offset <= 0`;
  field or base running past the pattern; field not inside `[instruction_offset,
  base_offset)`
- BODY: missing or negative `body_offset`

Ignore silently: unknown fields. Report and skip: unknown `record` kinds.

---

## 10. Worked example (verified)

Exported from cs2 `client.dll` build **14177**, resolved against build **14181**:

```
pattern              0F 28 F0 E8 ? ? ? ? 48 8B 6C 24 50
instruction_offset   3      -> byte at match+3 is E8 (call rel32)
displacement_offset  4
displacement_size    4
base_offset          8      -> end of the call instruction

match  = 0x16B807   (unique in 14181)
disp   = signed_le(image[0x16B80B .. 0x16B80F]) = -18367
target = 0x16B807 + 8 + (-18367) + 0 = 0x167050   ✓
```

BODY, `TraceShape`, `body_offset = 0x1C9`, stable across both builds:

```
match           = 0x9E62DD           (unique in 14181)
candidate_start = 0x9E62DD - 0x1C9 = 0x9E6114
0x9E6114 is a .pdata RUNTIME_FUNCTION begin       ✓
0x9E62DD lies within [0x9E6114, 0x9E6405)         ✓
target = 0x9E6114
```

Reproduce both with:

```
python tools/cfs6_resolve.py <file.cfs> <client.dll> --name ConVarRef_GetFloat --verbose
```
