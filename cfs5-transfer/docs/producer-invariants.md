# Producer invariants

This document is authoritative for declarations, candidate generation, type
transport, and export orchestration.

## Declaration evidence

`member_offset` reads its value from a live IDA field. No field means no item.
Candidate sites may originate only from `stroff_xref`, `selected_operand`, or
`hexrays_memptr`; the format reader enforces this closed set. A displacement
search is a prefilter, never proof of owner/member association.

Correct pointer typing can still yield no IDA field xrefs. Explicit sites name
where evidence exists, not what value it should produce. The exporter decodes
each site and drops one that disagrees with the live field.

`element_stride`, `constant`, and `object_extent` assert values because no IDA
field owns them. Every supplied site must support the assertion; a contradictory
site rejects the declaration. `LEA_SCALE_CHAIN` is the only compound stride
recipe. Extents use `align_up(displacement + access_width, alignment)`.

## VALUE arithmetic

One convention owns adjustment arithmetic:

```text
reported = encoded + value_adjust
encoded  = reported - value_adjust
```

`Declaration.site_value` and `reported_value` are the implementation source of
truth. The producer searches for the encoded value; the consumer applies the
adjustment once. Tests must include positive, negative, and zero adjustments.

The extraction recipe must reproduce `source.expected_value` on the source
image. Use the signed semantic value for sign-extended immediates: an encoded
imm8 `FF` with `signed: true` is `-1`.

## Candidate construction

- Wildcard the extracted field; drift is the value being measured.
- Extraction offsets come from the decoder, never caller-entered byte offsets.
- A pattern must match exactly once in its declared search domain.
- VALUE candidates require the VALUE exact-byte floor.
- Keep a CONST candidate only when it is the sole candidate; multiple CONST
  records would create fake confirmation.
- Grow anchored VALUE windows by bytes in both directions, clamped to the
  owning function. Probe the widest envelope first: a non-unique envelope
  proves every contained window non-unique.
- BODY ownership must map `match - body_offset` exactly to a function start.
- REL stores the end of the complete anchor instruction as `base_offset` and
  revalidates the decoded field and target at import.
- Structural VTABLE and STRING_REL patterns are bounded confirmation evidence,
  not image-wide locators.

Candidate generation can rarely fail on its first pass and succeed on an
identical second pass because of IDA state. Retry only an already-failed
declaration once and emit `MEMBER_FLAKY_FIRST_PASS` when it recovers.

Keep refusal stages distinct:

- `MEMBER_NO_FIELD`: backing field absent.
- `MEMBER_NO_SITE`: no evidence site exists.
- `MEMBER_NO_PATTERN`: sites exist but none yields an exportable candidate.
- `MEMBER_DISCARDED`: candidates exist but all disagree with the expected value.

## Selection and agreement

Search ENTRY, external REL, and BODY axes independently; a successful axis does
not suppress the others. Rank is authoritative and score is diagnostic, lower
being better. Pinned caller evidence is not scored out.

Consumers evaluate every candidate. Same answer means confirmation. Different
answers mean conflict. Two distinct items claiming one address also conflict.

## Type transport

Transport binary `tinfo_t`, not C declarations. Export the transitive closure of
referenced named types, materialize complete UDT/enum bodies, replace ordinal
references with names, and deduplicate local types across the file.

Member-owner types travel even when no function/global prototype references
them; blank destinations need them to validate and reconstruct declarations.
Import is non-destructive: complete destination types are immutable, forward
declarations may be upgraded, and missing types are registered in multiple
passes.

## Persistence and export modes

Registry entries store names, not addresses. Declarations store identity and
evidence, never a cached member offset. Every netnode write is read-back
verified.

Append is an atomic rewrite: generate a temporary catalogue, carry unrelated
old records verbatim, validate, then replace. Image and build identity must
match. A regenerated item replaces its parent, candidates, item type payload,
and directly required local types.

`export_selected` is the strict incremental path. Resolve the entire selection
before generation; every selected item must regenerate successfully; validate
the completed temporary file before replacing the destination. Never fall back
to a full export or retain a stale selected record.

## API boundary

UI and programmatic calls use `export.export_to_path`; fixes belong in the
engine. Service modules never prompt or show modal UI. Return the shared result
envelope and preserve per-item diagnostics.
