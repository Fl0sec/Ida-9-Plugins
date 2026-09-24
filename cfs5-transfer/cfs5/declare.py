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
#
# 2: `sites` (a list) replaces the single `site_ea`/`site_op` pair, and adds
#    `discovery` plus `asserted_value`. Version 1 records still load -- their
#    one site becomes a one-element list -- because re-declaring by hand is
#    exactly the work this is meant to stop repeating.
DECL_VERSION = 3

# How a declaration's candidate sites are found.
#   sites_only      use exactly the sites given; never scan.
#   sites_plus_auto use the given sites AND automatic discovery, then merge.
# Default is sites_only: an agent asking for specific evidence should get a
# deterministic, fast export. sites_plus_auto buys resilience -- independent
# automatic candidates fail for different reasons than a hand-picked one -- at
# the cost of decompiling, so it is opt-in.
DISCOVER_SITES_ONLY = "sites_only"
DISCOVER_SITES_PLUS_AUTO = "sites_plus_auto"
DISCOVER_AUTO = "auto"
VALID_DISCOVERY = (
    DISCOVER_SITES_ONLY, DISCOVER_SITES_PLUS_AUTO, DISCOVER_AUTO,
)

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


def normalize_sites(sites):
    """[(ea, op), ...] deduplicated, order-stable, sentinels dropped.

    BADADDR and a negative operand index mean "no site". Normalizing here
    rather than at every call site is what stops a sentinel from being stored
    as a real address, rendered as `BADADDR` in the UI, and fed to candidate
    generation as a `selected_operand` it never was.
    """
    out = []
    seen = set()
    for site in sites or ():
        if isinstance(site, dict):
            ea, op = site.get("ea"), site.get("op")
        else:
            try:
                ea, op = site
            except (TypeError, ValueError):
                raise DeclarationError(
                    "site %r is not an (ea, operand) pair" % (site,)
                )
        if ea is None or op is None:
            continue
        try:
            ea, op = int(ea), int(op)
        except (TypeError, ValueError):
            raise DeclarationError(
                "site %r does not hold two integers" % (site,)
            )
        if ea == _NO_EA or ea == 0 or op < 0:
            continue
        if (ea, op) not in seen:
            seen.add((ea, op))
            out.append((ea, op))
    return out


class Declaration:
    """One user-declared derived value, as persisted in the IDB."""

    __slots__ = (
        "semantic", "owner", "name", "member", "sites", "discovery",
        "asserted_value", "value_adjust", "site_options", "version",
    )

    def __init__(self, semantic, owner, name, member=None, sites=(),
                 discovery=DISCOVER_SITES_ONLY, asserted_value=None,
                 value_adjust=0, version=DECL_VERSION):
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
        self.sites = normalize_sites(sites)
        self.site_options = {}
        for site in sites or ():
            if not isinstance(site, dict):
                continue
            if site.get("ea") is None or site.get("op") is None:
                continue
            key = (int(site["ea"]), int(site["op"]))
            options = {}
            for field in ("window_start_ea", "access_width", "alignment"):
                if site.get(field) is not None:
                    try:
                        options[field] = int(site[field])
                    except (TypeError, ValueError):
                        raise DeclarationError("%s must be an integer" % field)
            if options:
                if options.get("window_start_ea", 1) <= 0:
                    raise DeclarationError("window_start_ea must be positive")
                if options.get("access_width", 1) <= 0:
                    raise DeclarationError("access_width must be positive")
                if options.get("alignment", 1) <= 0:
                    raise DeclarationError("alignment must be positive")
                self.site_options[key] = options

        if discovery not in VALID_DISCOVERY:
            raise DeclarationError(
                "unknown discovery mode %r (expected one of %s)"
                % (discovery, ", ".join(VALID_DISCOVERY))
            )
        # Sites-based modes without a site would silently produce nothing,
        # which is the failure this whole model exists to avoid.
        if not self.sites and discovery != DISCOVER_AUTO:
            discovery = DISCOVER_AUTO
        self.discovery = discovery

        # Only a semantic with no backing IDA field may assert its own value;
        # for a member the offset is read from the database, and accepting a
        # caller's number there would turn a derived fact into a hand-counted
        # one -- the exact failure this model was built to prevent.
        if asserted_value is None:
            self.asserted_value = None
        elif semantic == cfs6.SEM_MEMBER_OFFSET:
            raise DeclarationError(
                "a member_offset takes its value from the IDA member, never "
                "from an asserted one"
            )
        else:
            self.asserted_value = int(asserted_value)

        if semantic != cfs6.SEM_MEMBER_OFFSET:
            if self.asserted_value is None:
                raise DeclarationError(
                    "%s has no IDA field to read a value from, so it must "
                    "assert one" % semantic
                )
            if not self.sites:
                raise DeclarationError(
                    "%s cannot be discovered -- nothing in the database "
                    "associates an instruction with it -- so it requires at "
                    "least one explicit site" % semantic
                )

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
        return bool(self.sites)

    @property
    def scan_allowed(self):
        """Whether the exporter may spend decompiles discovering more sites."""
        return self.discovery in (DISCOVER_AUTO, DISCOVER_SITES_PLUS_AUTO)

    @property
    def needs_ida_member(self):
        """Whether `expected_value` comes from a live IDA field."""
        return self.semantic == cfs6.SEM_MEMBER_OFFSET

    # -- the value_adjust convention ---------------------------------------
    #
    # One direction of arithmetic, stated once, here. Three different numbers
    # are involved and conflating any two of them produces a declaration that
    # can never be exported:
    #
    #   site value      what the instruction literally encodes
    #   value_adjust    what a consumer adds to the site value
    #   reported value  the answer -- which must equal the IDA member, or the
    #                   asserted value for a semantic with no field
    #
    # so `reported = site + adjust`, and therefore `site = reported - adjust`.
    # An exporter learns the reported value *first* (IDA supplies it) and has
    # to work backwards to know what to look for at the site. Searching the
    # site for the reported value is the defect this pair exists to prevent:
    # for any non-zero adjust the site does not encode that number, so the
    # site yields no candidate at all and the declaration is refused for
    # "no candidate" when the real cause was the search target.

    def site_value(self, reported_value):
        """What an instruction must encode in order to report `reported_value`."""
        return int(reported_value) - self.value_adjust

    def reported_value(self, site_value):
        """What a consumer reports for an instruction encoding `site_value`."""
        return int(site_value) + self.value_adjust

    def to_dict(self):
        return {
            "version": self.version,
            "semantic": self.semantic,
            "owner": self.owner,
            "name": self.name,
            "member": self.member,
            "sites": [dict({"ea": ea, "op": op},
                           **self.site_options.get((ea, op), {}))
                      for ea, op in self.sites],
            "discovery": self.discovery,
            "asserted_value": self.asserted_value,
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

    sites = data.get("sites")
    if sites is None:
        # Version 1 stored one site in two scalar fields. Migrate rather than
        # discard: re-picking a site by hand is exactly the work that
        # persisting it was meant to stop repeating.
        sites = [{"ea": data.get("site_ea"), "op": data.get("site_op")}]

    discovery = data.get("discovery")
    if discovery not in VALID_DISCOVERY:
        # A v1 record never restricted discovery, so it keeps scanning; the
        # sites-only default applies to declarations made under v2, which is
        # where a caller actually asked for exactly those sites.
        discovery = DISCOVER_AUTO

    return Declaration(
        semantic=data.get("semantic"),
        owner=data.get("owner"),
        name=data.get("name"),
        member=data.get("member"),
        sites=sites,
        discovery=discovery,
        asserted_value=data.get("asserted_value"),
        value_adjust=data.get("value_adjust", 0),
        version=DECL_VERSION,
    )


def make_member(owner, name, member=None, sites=(),
                discovery=DISCOVER_SITES_ONLY, value_adjust=0):
    """A `member_offset` declaration. Value always comes from the IDA field."""
    return Declaration(
        cfs6.SEM_MEMBER_OFFSET, owner, name, member=member,
        sites=sites, discovery=discovery, value_adjust=value_adjust,
    )


def make_stride(owner, name, value, sites, value_adjust=0):
    """An `element_stride` declaration: a constant encoded in code.

    Unlike a member offset there is no field in the database to read, so the
    caller asserts the value and must point at the instructions that encode
    it. That is a weaker guarantee than `member_offset` gets, and deliberately
    visible as one: the export gate becomes "every supplied site decodes to
    the asserted number" rather than "every site agrees with IDA".

    It also cannot be discovered. No index, decompiler node or type in the
    database associates an instruction with "the stride of this array", and
    finding other instructions encoding the same number would be numeric
    coincidence, not evidence -- the one thing the candidate rules forbid.
    """
    return Declaration(
        cfs6.SEM_ELEMENT_STRIDE, owner, name, member=name,
        sites=sites, discovery=DISCOVER_SITES_ONLY,
        asserted_value=value, value_adjust=value_adjust,
    )


def make_constant(owner, name, value, sites, value_adjust=0):
    """A `constant` declaration: a number that exists only in the code.

    Structurally identical to `element_stride` -- assert the value, name the
    instructions that encode it, no discovery -- and deliberately so: both are
    the same claim about the same kind of evidence, and only the meaning a
    consumer attaches to the number differs. A bit position tested by
    `bt reg, 0xB` or a sentinel compared against a field has no owning IDA
    field to source a value from, which is exactly the case this covers.

    `owner` is a namespace, not a claim that the type has such a field.

    A constant is usually encoded as a small immediate, so its pattern is more
    likely than a member offset's to fail the VALUE uniqueness test. That
    refusal is correct and is not softened here: a non-unique pattern resolves
    to nothing on the consumer's side, so exporting it would publish a
    signature that cannot be used.
    """
    return Declaration(
        cfs6.SEM_CONSTANT, owner, name, member=name,
        sites=sites, discovery=DISCOVER_SITES_ONLY,
        asserted_value=value, value_adjust=value_adjust,
    )


def make_extent(owner, name, value, sites, value_adjust=0):
    """An object extent derived as align_up(displacement + width, alignment)."""
    if int(value_adjust):
        raise DeclarationError("object_extent does not use value_adjust")
    for site in sites or ():
        try:
            width = int(site.get("access_width", 0)) if isinstance(site, dict) else 0
        except (TypeError, ValueError):
            width = 0
        if width <= 0:
            raise DeclarationError(
                "object_extent sites require a positive access_width"
            )
    return Declaration(
        cfs6.SEM_OBJECT_EXTENT, owner, name, member=name,
        sites=sites, discovery=DISCOVER_SITES_ONLY,
        asserted_value=value,
    )
