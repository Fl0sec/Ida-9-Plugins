"""The declaration model: what the user said a derived value *is*.

A declaration is the small amount of information IDA cannot work out on its
own -- the canonical name, the owning type, the semantic -- plus a pointer to
the site the user picked. Everything else (the offset, the field position and
width, the operand index, the candidate patterns) is derived from the database
at export time and is deliberately **not** stored here.

That split is the point. Storing a byte offset would freeze a hand-counted
number into the IDB and reproduce the failure mode of a hand-written signature
table; re-deriving it means that improving the types in the database improves
the export, and that a field which moved is noticed rather than silently
carried forward.

Free of any `ida_*` import so the model and its validation can be unit tested;
`cfs5/store.py` puts these in the IDB and `cfs5/sigs.py` turns them into
candidates.
"""

from . import cfs6


# Bumped only when a stored declaration's fields change meaning. A declaration
# written by a newer plugin is refused rather than misread.
DECL_VERSION = 1

# A record name has to survive as a JSON string, an IDB blob and a C++
# identifier in whatever the consumer generates, so it is a plain identifier.
_IDENT_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
)


# IDA's BADADDR. Spelled out rather than imported so this module stays free of
# any `ida_*` dependency and remains unit-testable outside IDA.
_NO_EA = 0xFFFFFFFFFFFFFFFF


class DeclarationError(ValueError):
    """A declaration that cannot be stored or exported as written."""


def _check_identifier(label, value):
    text = (value or "").strip()
    if not text:
        raise DeclarationError("%s must not be empty" % label)
    if text[0].isdigit():
        raise DeclarationError("%s %r must not start with a digit" % (label, text))
    bad = sorted(set(c for c in text if c not in _IDENT_CHARS))
    if bad:
        raise DeclarationError(
            "%s %r contains unusable character(s): %s"
            % (label, text, " ".join(repr(c) for c in bad))
        )
    return text


class Declaration:
    """One user-declared derived value, as persisted in the IDB."""

    __slots__ = (
        "semantic", "owner", "name", "member", "site_ea", "site_op",
        "value_adjust", "version",
    )

    def __init__(self, semantic, owner, name, member=None, site_ea=None,
                 site_op=None, value_adjust=0, version=DECL_VERSION):
        if semantic not in cfs6.VALID_SEMANTICS:
            raise DeclarationError("unsupported semantic %r" % (semantic,))
        self.semantic = semantic
        self.owner = _check_identifier("owner", owner)
        # `name` is what the consumer will see; `member` is the field in the
        # IDB it is derived from. They are usually the same, but a project
        # naming convention should not force a rename inside the database --
        # and the lookup that produces expected_value must use the real field
        # name or it would silently find nothing.
        self.name = _check_identifier("name", name)
        self.member = _check_identifier("member", member or name)
        # BADADDR and a negative operand index mean "no site". Normalizing here
        # rather than at every call site is what stops a sentinel from being
        # stored as a real address, rendered as `BADADDR` in the UI, and fed to
        # candidate generation as a `selected_operand` it never was.
        self.site_ea = None if site_ea is None else int(site_ea)
        self.site_op = None if site_op is None else int(site_op)
        if self.site_ea == _NO_EA or (self.site_op is not None
                                      and self.site_op < 0):
            self.site_ea = None
            self.site_op = None
        self.value_adjust = int(value_adjust)
        self.version = int(version)

    @property
    def id(self):
        return cfs6.derived_item_id(self.semantic, self.owner, self.name)

    @property
    def qualified(self):
        return "%s::%s" % (self.owner, self.name)

    @property
    def has_site(self):
        return self.site_ea is not None and self.site_op is not None

    def to_dict(self):
        return {
            "version": self.version,
            "semantic": self.semantic,
            "owner": self.owner,
            "name": self.name,
            "member": self.member,
            "site_ea": self.site_ea,
            "site_op": self.site_op,
            "value_adjust": self.value_adjust,
        }

    def __repr__(self):
        return "<Declaration %s>" % self.id


def member_id(owner, name):
    """The stored id a `member_offset` declaration for `owner.name` would use.

    Lets a caller ask "is this already declared?" without building a
    Declaration first.
    """
    return cfs6.derived_item_id(cfs6.SEM_MEMBER_OFFSET, owner, name)


def from_dict(data):
    """Rebuild a Declaration from its stored form. Raises DeclarationError."""
    if not isinstance(data, dict):
        raise DeclarationError("stored declaration is not an object")

    version = int(data.get("version", 0))
    if version > DECL_VERSION:
        raise DeclarationError(
            "declaration was written by a newer plugin (version %d > %d); "
            "update the plugin rather than reading it with guesses"
            % (version, DECL_VERSION)
        )

    return Declaration(
        semantic=data.get("semantic"),
        owner=data.get("owner"),
        name=data.get("name"),
        member=data.get("member"),
        site_ea=data.get("site_ea"),
        site_op=data.get("site_op"),
        value_adjust=data.get("value_adjust", 0),
        version=version or DECL_VERSION,
    )


def make_member(owner, name, member=None, site_ea=None, site_op=None,
                value_adjust=0):
    """A `member_offset` declaration."""
    return Declaration(
        cfs6.SEM_MEMBER_OFFSET, owner, name, member=member,
        site_ea=site_ea, site_op=site_op, value_adjust=value_adjust,
    )
