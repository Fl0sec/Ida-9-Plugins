"""IDA-free planning helpers for portable member materialization."""


def create_batches(rows):
    """Group safe creates by owner and reject overlap within the selection."""
    batches = {}
    for row in rows:
        if row["action"] == "create":
            batches.setdefault(row["owner"], []).append(row)
    conflicts = []
    for owner, batch in batches.items():
        batch.sort(key=lambda row: (int(row["resolved_offset"]), row["id"]))
        for previous, current in zip(batch, batch[1:]):
            previous_end = int(previous["resolved_offset"]) + int(previous["field_schema"]["width"])
            if previous_end > int(current["resolved_offset"]):
                conflicts.append({"owner": owner, "id": current["id"],
                                  "reason": "selected member ranges overlap"})
    return batches, conflicts
