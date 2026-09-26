"""IDA-free outcome policy for bounded annotated snapshot exports."""


def unexportable_issue(unit, raw):
    """Return a durable exclusion for safe candidate absence, else ``None``.

    A missing unique signature is expected when a human annotation identifies a
    clone-family or vtable-only symbol.  It is not an engine failure and must
    not abandon unrelated snapshot work.  Real exporter errors remain fatal.
    """
    if raw.get("error") or int(raw.get("written", 0)) == 1:
        return None
    uncovered = list(raw.get("uncovered") or [])
    source = uncovered[0] if uncovered else {}
    issue = {
        "kind": str(unit["kind"]), "name": str(unit["name"]),
        "reason": str(source.get("reason") or "no safe unique candidate"),
    }
    if source.get("diagnosis"):
        issue["diagnosis"] = source["diagnosis"]
    return issue
