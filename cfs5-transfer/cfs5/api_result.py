"""One result envelope shared by every public CFS API branch."""


def result(ok=False, partial=False, error=None, unresolved=(), **extra):
    out = {
        "ok": bool(ok),
        "partial": bool(partial),
        "error": error,
        "unresolved": list(unresolved),
    }
    out.update(extra)
    return out
