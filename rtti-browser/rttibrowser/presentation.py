"""IDA-free filtering and compact display policy for RTTI chooser rows."""


_NOISE_MARKERS = (
    "<lambda",
    "`lambda",
    "{lambda",
    "<unnamed",
    "`anonymous namespace'",
    "anonymous namespace",
)


def descriptor_fallback(raw):
    """Readable fallback for an MSVC type descriptor IDA did not demangle."""
    if not isinstance(raw, str) or not raw.startswith(".?"):
        return raw
    decorated = raw[1:]
    if len(raw) > 6 and raw[2:4] in ("AV", "AU") and raw.endswith("@@"):
        body = raw[4:-2]
        if "?" not in body and "$" not in body and "@" not in body:
            return body
    return decorated


def is_compiler_generated(name):
    """Whether a validated RTTI name is low-signal compiler machinery."""
    text = str(name or "").strip()
    lowered = text.casefold()
    return (
        not text
        or text.startswith(("?", ".?"))
        or any(marker in lowered for marker in _NOISE_MARKERS)
    )


def compact(text, limit=96):
    """Middle-truncate text while preserving both identity-bearing ends."""
    value = str(text or "")
    if len(value) <= limit:
        return value
    if limit < 12:
        return value[:limit]
    tail = max(5, limit // 4)
    head = limit - tail - 3
    return "%s...%s" % (value[:head], value[-tail:])


def hierarchy_summary(names, limit=150, maximum_bases=6):
    """Compact a hierarchy and state how many validated bases were omitted."""
    values = [str(name) for name in names]
    visible = values[:maximum_bases]
    text = " : ".join(visible)
    omitted = len(values) - len(visible)
    if omitted:
        text += " : ... (+%d bases)" % omitted
    return compact(text, limit)
