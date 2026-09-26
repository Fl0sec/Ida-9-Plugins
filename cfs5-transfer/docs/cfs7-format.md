# CFS7 rolling catalogue format

CFS7 is an explicit rolling format. CFS6 stays unchanged: one header describes
one source image, and append/selected export require matching identity.

## Header

The first JSONL record is a CFS header with `version: 7`. Its `target` object
contains the image and build against which the complete output was last
validated. This target is an audit fact, not a resolver gate.

## Candidate provenance

Every candidate has a required `provenance` object containing immutable
`image` and `build` objects. Revalidation updates diagnostic source RVAs for
the target but never changes provenance. Rank remains quality order; build age
is never a ranking input.

## Refresh rules

The refresh engine evaluates every candidate against the target. A candidate
survives only when it uniquely resolves and satisfies its address, value, or
patch checks. Candidate disagreement remains a conflict. Equivalent candidates
are deduplicated and the existing per-kind limits apply.

Type records are target-only. They may be written for exact active-IDB records
selected during a refresh; they are never inherited from an earlier catalogue.
