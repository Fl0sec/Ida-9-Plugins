# Catalogue import and producer-state migration

This document is authoritative for `cfs5/importer.py` and `cfs5/api_import.py`.

## Two operations

Catalogue application changes the destination analysis:

- resolve functions and globals against the destination image;
- protect real destination names;
- register missing named types without replacing complete definitions;
- merge function prototypes and apply safe global types.

It also validates every catalogue candidate against the destination image.
Derived values and patches are validation-only during this phase: import never
writes patch bytes or producer state. Each outcome includes every candidate's
rank, origin, status and exact refusal reason, so a partly portable item can
report (for example) two agreements and three rejected candidates rather than
a generic `unsafe`.

For a resolved member candidate, ordinary import reports destination evidence
separately: `destination-agrees`, `destination-unverified` (no pre-existing
field), or `destination-disagrees`. The unavailable case is a warning, not a
CFS candidate failure. Ordinary import does not register transported local
types or create/repair member layouts. `import_and_migrate()` explicitly opts
into type transport and producer-state reconstruction, while retaining a
pre-transport snapshot so an imported layout cannot become its own proof.

Producer-state migration prepares the destination to produce its own next
catalogue:

- register successfully applied functions and globals;
- reconstruct derived declarations from destination-resolved VALUE evidence;
- reconstruct patch sites after opcode, span, and mnemonic checks;
- retain structural locator declarations where the address item was applied.

`import_and_migrate` runs them in that order. They remain separate calls so a
caller can apply analysis without adopting producer state.

## Portability boundary

Source addresses never cross the boundary. A migrated site comes from a unique
candidate match in the destination image plus the candidate's decoder-derived
instruction offset and operand index.

For member offsets, the transported owner type is bootstrap material, not
proof. Persist the declaration only when:

1. its VALUE candidates agree on one destination value; and
2. the destination IDA field independently exists at that value.

A missing field is destination-unverified during ordinary import and cannot be
migrated. A type/code disagreement is unresolved for migration. Never repair
the type from the same pattern and then treat the agreement as independent
evidence.

Strides, constants, and extents have no backing IDA field. Their agreeing
destination candidates supply the migrated asserted value. Report a difference
from `source.expected_value` as drift.

## Resolution outcomes

- Zero matches: `not-found`.
- Multiple matches: `ambiguous`.
- Decode, ownership, target, operand, opcode, or span failure: `unsafe`.
- Independent candidates resolving differently: `conflict`.
- A protected destination name: preserve it and report the item.

`import_catalogue()` returns an `outcomes` row for every function, global,
derived value and patch. `unresolved` remains the compact failures-only view.
For function/global candidates, unsafe diagnostics retain the failed boundary,
decode, mapping, ownership, interior-function, or claim check. For VALUE and
SITE candidates, validation reuses the migration decoder and patch opcode/span
checks without applying a patch.

Structural `VTABLE` and `STRING_REL` modes are not image-wide patterns. The
catalogue importer skips them unless another candidate or an existing correct
name establishes the item. Migration can then preserve their locator metadata.

## Transaction policy

`require_all=False` is the normal cross-build policy: plan every record, commit
the valid subset as one verified transaction, and return every rejected record
in `unresolved`.

`require_all=True` is the strict gate: any unresolved state record refuses all
producer-state writes. Catalogue application is a preceding, distinct phase
and is not rolled back by a state refusal.

Before committing, reject any migrated declaration or patch that would replace
a different existing producer record. On a write failure, restore registry,
sites, locators, declarations, and patches from the pre-write snapshot and
report whether rollback verification succeeded.

## Completion checks

- Offline tests and `tools/check.py` pass.
- A disposable destination IDB reports structured outcomes for every item.
- Re-export from the migrated IDB succeeds for every committed producer record.
- Repeating the same migration is idempotent.
