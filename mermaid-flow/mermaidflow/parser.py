"""Mermaid flowchart subset -> a plain node/edge model.

Deliberately free of every `ida_*` import. This is the one layer of the plugin
that can be executed and tested outside IDA, which is the only real test an IDA
plugin gets -- keep it that way, and keep IDA concepts (addresses, colours,
graph ids) out of it. Resolving a node's `target` to an address is the view
layer's job.

The parser is intentionally forgiving: flowcharts are pasted from LLM output and
from mermaid.live, so an unsupported construct produces a warning and is
skipped, never an exception. Anything it cannot place is reported through
`FlowGraph.warnings` for the caller to show.
"""

import re


DEFAULT_SHAPE = "rect"

# Shapes, longest opening delimiter first: `_split_shape` takes the first entry
# whose open *and* close both match, so `[[x]]` cannot be mistaken for `[x]`.
_SHAPES = [
    ("([", "])", "stadium"),
    ("[[", "]]", "subroutine"),
    ("[(", ")]", "cylinder"),
    ("((", "))", "circle"),
    ("{{", "}}", "hexagon"),
    ("[/", "/]", "parallelogram"),
    ("[\\", "\\]", "parallelogram"),
    ("[/", "\\]", "trapezoid"),
    ("[\\", "/]", "trapezoid"),
    (">", "]", "flag"),
    ("[", "]", "rect"),
    ("(", ")", "round"),
    ("{", "}", "decision"),
]

# Shapes that read as a branch/condition rather than a step. The view layer
# colours these differently -- IDA draws every node as a rectangle, so this is
# the only way a decision stays visually distinct.
DECISION_SHAPES = frozenset(["decision", "hexagon"])

# What may appear inside an inline link label (`-- Yes -->`). Excluding the
# arrow head and every bracket is what stops a chain like
# `A --> B["two"] --> C` from being read as one link whose label is `> B["two"]`
# -- the label is lazy, so without this it happily spans to the next link.
# `-` stays legal: "failure is non-fatal" is a realistic label.
_LABEL_CHARS = r"[^<>\[\]{}()|\n]"

# One link between two nodes, in every form the flowchart grammar allows:
#   -->            ---          -- label -->        -->|label|
#   -.->           -. label .->
#   ==>            == label ==>
# The three alternatives are ordered dotted / thick / solid because a dotted
# link starts with a single `-` that the solid branch must not claim.
_LINK_RE = re.compile(
    r"""
    (?P<back><)?
    (?:
        -\.\s*(?:(?P<dot_label>LBL*?)\s*\.)?->
      | ={2,}\s*(?:(?P<thick_label>LBL*?)\s*={2,})?>
      | -{2,}\s*(?:(?P<solid_label>LBL*?)\s*-{2,})?>?
    )
    (?:\s*\|\s*(?P<pipe_label>[^|]*?)\s*\|)?
    """.replace("LBL", _LABEL_CHARS),
    re.VERBOSE,
)

_NODE_ID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-]*")

# `click A "target"`, `click A href "target"`, `click A call fn()`.
_CLICK_RE = re.compile(
    r"^click\s+(?P<id>[A-Za-z_][A-Za-z0-9_\-]*)\s+"
    r"(?:href\s+|call\s+)?(?P<target>\"[^\"]*\"|'[^']*'|\S+)",
    re.IGNORECASE,
)

_HEADER_RE = re.compile(
    r"^(?:flowchart|graph)\s+(?P<direction>TB|TD|BT|RL|LR)\b", re.IGNORECASE
)

# Presentational directives we knowingly ignore: they carry no topology.
_IGNORED_RE = re.compile(
    r"^(classDef|class|style|linkStyle|direction|accTitle|accDescr)\b", re.IGNORECASE
)

_BR_RE = re.compile(r"<br\s*/?>", re.IGNORECASE)

_ENTITIES = [
    ("&quot;", '"'), ("#quot;", '"'),
    ("&apos;", "'"), ("#apos;", "'"),
    ("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"),
    ("#35;", "#"), ("#59;", ";"),
]

_OPENERS = "[({"
_CLOSERS = "])}"


class Node(object):
    """One flowchart node. `target` is the raw jump token, unresolved."""

    def __init__(self, key, label=None, shape=DEFAULT_SHAPE):
        self.key = key
        self.label = label if label is not None else key
        self.shape = shape
        self.target = None
        self.labelled = label is not None

    @property
    def is_decision(self):
        return self.shape in DECISION_SHAPES

    def __repr__(self):
        return "Node(%r, %r, %s)" % (self.key, self.label, self.shape)


class Edge(object):
    """One link. `style` is solid / dotted / thick; `label` may be None."""

    def __init__(self, src, dst, label=None, style="solid"):
        self.src = src
        self.dst = dst
        self.label = label
        self.style = style

    def __repr__(self):
        return "Edge(%s->%s, %r, %s)" % (self.src, self.dst, self.label, self.style)


class FlowGraph(object):
    def __init__(self):
        self.direction = "TD"
        self.nodes = {}          # key -> Node, in first-seen order
        self.edges = []
        self.warnings = []

    # -- construction ------------------------------------------------------

    def node(self, key, label=None, shape=None):
        """Get or create a node, upgrading a bare reference once its label
        arrives. A chain like `E1 --> F` may name `F` long before the line that
        declares `F["Create Device"]`, so a later label always wins.
        """
        existing = self.nodes.get(key)
        if existing is None:
            existing = Node(key, label, shape or DEFAULT_SHAPE)
            self.nodes[key] = existing
            return existing

        if label is not None and not existing.labelled:
            existing.label = label
            existing.labelled = True
        if shape is not None and shape != DEFAULT_SHAPE:
            existing.shape = shape
        return existing

    def link(self, src, dst, label=None, style="solid"):
        """Add an edge, merging a duplicate rather than drawing it twice.

        Mermaid renders `K --> L` and `K -. "non-fatal" .-> L` as two separate
        arrows; IDA would draw them on top of each other, so the informative
        one absorbs the other.
        """
        for edge in self.edges:
            if edge.src == src and edge.dst == dst:
                if label and not edge.label:
                    edge.label = label
                if style != "solid" and edge.style == "solid":
                    edge.style = style
                self.warnings.append(
                    "merged duplicate edge %s -> %s" % (src, dst)
                )
                return edge

        edge = Edge(src, dst, label, style)
        self.edges.append(edge)
        return edge

    # -- access ------------------------------------------------------------

    def ordered_nodes(self):
        return list(self.nodes.values())

    def index_of(self):
        """Map node key -> position, i.e. the IDA graph node id it will get."""
        return {key: i for i, key in enumerate(self.nodes)}


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------

def clean_label(text):
    """Unquote a label and turn Mermaid's markup into plain multi-line text."""
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1]
    text = _BR_RE.sub("\n", text)
    for entity, char in _ENTITIES:
        text = text.replace(entity, char)
    return "\n".join(part.strip() for part in text.split("\n")).strip()


def _split_shape(rest):
    """Split `["label"]` into (label, shape); returns (None, None) if bare."""
    for open_tok, close_tok, kind in _SHAPES:
        if (len(rest) > len(open_tok) + len(close_tok)
                and rest.startswith(open_tok) and rest.endswith(close_tok)):
            return rest[len(open_tok):-len(close_tok)], kind
    return None, None


def _iter_statements(text):
    """Yield statement strings, stripping fences, comments and `;` joins."""
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("```"):          # ```mermaid ... ```
            continue
        if line.startswith("%%"):           # comment or %%{init}%% directive
            continue
        for part in _split_top_level(line, ";"):
            part = part.strip()
            if part:
                yield part


def _split_top_level(line, sep):
    """Split on `sep`, ignoring separators inside brackets or quotes."""
    parts = []
    depth = 0
    quote = None
    start = 0
    for i, char in enumerate(line):
        if quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char in _OPENERS:
            depth += 1
        elif char in _CLOSERS:
            depth = max(0, depth - 1)
        elif char == sep and depth == 0:
            parts.append(line[start:i])
            start = i + 1
    parts.append(line[start:])
    return parts


def _find_links(statement):
    """Locate every link operator at bracket/quote depth 0.

    Scanning character by character rather than running the regex over the whole
    string is what keeps a label like `A["step a --> b"]` from being torn in
    half by its own text.
    """
    links = []
    depth = 0
    quote = None
    i = 0
    length = len(statement)
    while i < length:
        char = statement[i]
        if quote:
            if char == quote:
                quote = None
            i += 1
            continue
        if char in "\"'":
            quote = char
            i += 1
            continue
        if char in _OPENERS:
            depth += 1
            i += 1
            continue
        if char in _CLOSERS:
            depth = max(0, depth - 1)
            i += 1
            continue
        if depth == 0 and char in "-=<":
            match = _LINK_RE.match(statement, i)
            if match and match.end() > match.start():
                links.append(match)
                i = match.end()
                continue
        i += 1
    return links


def _link_style_and_label(match):
    if match.group("dot_label") is not None or match.group(0).startswith("-."):
        style = "dotted"
        label = match.group("dot_label")
    elif match.group("thick_label") is not None or "==" in match.group(0):
        style = "thick"
        label = match.group("thick_label")
    else:
        style = "solid"
        label = match.group("solid_label")

    if match.group("pipe_label"):
        label = match.group("pipe_label")
    return style, clean_label(label) if label else None


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse(text):
    """Parse a Mermaid flowchart into a `FlowGraph`. Never raises on bad input."""
    graph = FlowGraph()
    if not text or not text.strip():
        graph.warnings.append("empty flowchart source")
        return graph

    seen_header = False
    subgraph_depth = 0

    for statement in _iter_statements(text):
        header = _HEADER_RE.match(statement)
        if header and not seen_header:
            graph.direction = header.group("direction").upper()
            seen_header = True
            if graph.direction not in ("TD", "TB"):
                graph.warnings.append(
                    "direction %s ignored: IDA lays graphs out top-down"
                    % graph.direction
                )
            continue

        if statement.lower().startswith("subgraph"):
            # Flattened rather than rejected: the nodes and edges inside are
            # still the topology the user cares about, and losing the visual
            # grouping beats losing the graph.
            subgraph_depth += 1
            if subgraph_depth == 1:
                graph.warnings.append("subgraph flattened (IDA has no grouping here)")
            continue

        if statement.lower() == "end":
            subgraph_depth = max(0, subgraph_depth - 1)
            continue

        click = _CLICK_RE.match(statement)
        if click:
            _apply_click(graph, click)
            continue

        if _IGNORED_RE.match(statement):
            continue

        _parse_chain(graph, statement)

    if not graph.nodes:
        graph.warnings.append("no nodes found -- is this a Mermaid flowchart?")
    return graph


def _apply_click(graph, match):
    key = match.group("id")
    target = match.group("target").strip()
    if len(target) >= 2 and target[0] == target[-1] and target[0] in "\"'":
        target = target[1:-1]
    graph.node(key).target = target.strip()


def _parse_chain(graph, statement):
    """Parse `A["x"] -- Yes --> B --> C{"y"}` into nodes and edges."""
    links = _find_links(statement)
    if not links:
        node = _parse_node_ref(graph, statement)
        if node is None and statement:
            graph.warnings.append("ignored line: %s" % statement)
        return

    segments = []
    cursor = 0
    for match in links:
        segments.append(statement[cursor:match.start()])
        cursor = match.end()
    segments.append(statement[cursor:])

    nodes = [_parse_node_ref(graph, segment) for segment in segments]

    for index, match in enumerate(links):
        src, dst = nodes[index], nodes[index + 1]
        if src is None or dst is None:
            graph.warnings.append("dropped link in: %s" % statement)
            continue
        style, label = _link_style_and_label(match)
        if match.group("back"):
            # `<-->` / `<--` : record both directions rather than lose one.
            graph.link(dst.key, src.key, label, style)
        graph.link(src.key, dst.key, label, style)


def _parse_node_ref(graph, segment):
    """Resolve one `ID` / `ID["label"]` segment into a Node, or None."""
    segment = segment.strip()
    if not segment:
        return None

    match = _NODE_ID_RE.match(segment)
    if not match:
        return None

    key = match.group(0)
    rest = segment[match.end():].strip()
    if not rest:
        return graph.node(key)

    raw_label, shape = _split_shape(rest)
    if raw_label is None:
        graph.warnings.append("unrecognised node shape: %s" % segment)
        return graph.node(key)

    return graph.node(key, clean_label(raw_label), shape)
