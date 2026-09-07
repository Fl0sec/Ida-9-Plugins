"""The IDA graph view: FlowGraph -> GraphViewer, plus node/address linking.

Two IDA constraints shape everything here, both verified against IDA 9.0:

* `edge_info_t` has colour, width and layout but **no text field**, so a
  Mermaid edge label (`-- Yes -->`, `-. "failure is non-fatal" .->`) cannot be
  drawn on the edge. Labels survive as edge colour plus `OnEdgeHint` hover
  text, and are folded into the node label when `show_edge_labels` is on.
* Every node is a rectangle -- there is no shape control -- so a Mermaid
  decision (`{...}`) is distinguished by colour and a `<>` marker instead.
"""

import re

import ida_funcs
import ida_graph
import ida_kernwin
import ida_name

from .common import BADADDR, ea_str, msg
from . import parser


# Node background colours, BGR (not RGB -- IDA is a Windows-native API).
COLOR_STEP = 0xF8F8F8          # ordinary step
COLOR_DECISION = 0xC0E8FF      # {...} branch: warm amber
COLOR_TERMINAL = 0xD8D8D8      # a node with no outgoing edge
COLOR_LINKED = 0xD8FFD8        # resolves to an address in this IDB
COLOR_FAILURE = 0xC8C8FF       # reached only by a "no"/failure edge

# Edge colours by meaning, so the labels IDA cannot draw are still readable.
EDGE_DEFAULT = 0x000000
EDGE_YES = 0x00A000
EDGE_NO = 0x0000C0
EDGE_DOTTED = 0x909090

# Edge labels read as yes/no branches; matched case-insensitively.
_YES_LABELS = frozenset(["yes", "y", "true", "ok", "success"])
_NO_LABELS = frozenset(["no", "n", "false", "fail", "failure", "error"])

# Labels wider than this wrap, so a long step does not stretch the whole graph.
WRAP_WIDTH = 38

_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# A single-word match inside a multi-word label is the weakest evidence this
# plugin acts on, so it is fenced in: a token must be at least this long and
# must not be one of the verbs and nouns every generated flowchart is built
# from. Without the fence, `Register process callback` would happily jump to
# whatever `process` happens to name.
MIN_TOKEN_LEN = 5
_TOKEN_STOPLIST = frozenset("""
    address alloc baseline buffer callback calculate check cleanup clear code
    context copy count create data delete device driver enable entry error
    event exit failed failure file filter find flag free handle header image
    index init initialize input install list load locate lock main memory name
    node object offset open output path pointer process queue read register
    resolve result return save section setup size start status stop store
    string success table test thread type unload value verify worker write
""".split())


def resolve_target(node):
    """Resolve a node to `(ea, why)`, or `(BADADDR, None)`.

    Four passes, most trustworthy first. An explicit `click` target wins; then
    the whole label; then each of its lines; and only then individual
    identifier tokens inside the label. That ordering is what makes
    `Install IRP_MJ_CREATE<br/>DispatchCreate` reach `DispatchCreate` without
    letting a one-word coincidence hijack a node that had an exact match
    available.

    A name is preferred over a raw address everywhere because an address dies
    the moment the IDB is rebased, while a name that stops resolving is a
    visible, useful signal rather than a silent wrong jump.

    `why` records what actually matched, so the hover hint can show it: a
    wrong link should be legible, not mysterious.
    """
    if node.target:
        ea = _resolve_token(node.target)
        if ea != BADADDR:
            return ea, "click target %s" % node.target

    label = node.label
    lines = [line for line in label.split("\n") if line.strip()]
    for candidate in [label] + lines:
        if "\n" in candidate and candidate is not label:
            continue
        ea = _resolve_token(candidate)
        if ea != BADADDR:
            return ea, "label %r" % candidate

    found = _resolve_from_tokens(label)
    if found is not None:
        ea, token = found
        return ea, "token %r in the label" % token

    return BADADDR, None


def _is_func_start(ea):
    try:
        func = ida_funcs.get_func(ea)
    except Exception:
        return False
    return func is not None and func.start_ea == ea


def _resolve_from_tokens(label):
    """Last-resort match on a single word of a multi-word label.

    Longest token first, and **only a function start counts**. A flowchart step
    means a routine; accepting data here is how `Register process-handle filter
    / Altitude 321500` ends up jumping to a global called `Altitude`. An exact
    label or line may still resolve to data -- that is a deliberate choice by
    whoever wrote the label -- and `click` can always name data explicitly.

    The stoplist and length floor also apply only here. An exact label has
    already been tried, so a node genuinely called `Process` still links; what
    is filtered out is `Process` extracted from `Register process callback`,
    which is precisely where a false jump would come from.
    """
    tokens = sorted(set(_TOKEN_RE.findall(label)), key=len, reverse=True)
    for token in tokens:
        if len(token) < MIN_TOKEN_LEN or token.lower() in _TOKEN_STOPLIST:
            continue
        ea = _resolve_token(token)
        if ea != BADADDR and _is_func_start(ea):
            return ea, token
    return None


def _resolve_token(token):
    if not token:
        return BADADDR
    token = token.strip()
    if not token:
        return BADADDR

    try:
        ea = ida_name.get_name_ea(BADADDR, token)
    except Exception:
        ea = BADADDR
    if ea != BADADDR:
        return ea

    # A bare address: `0x140001A90`, `140001A90`, or `sub_140001A90`.
    text = token[4:] if token.lower().startswith("sub_") else token
    try:
        value = int(text, 16)          # int() accepts a leading 0x here
    except (ValueError, TypeError):
        return BADADDR

    try:
        if ida_funcs.get_func(value) is not None:
            return value
    except Exception:
        pass
    return BADADDR


def _wrap(text, width=WRAP_WIDTH):
    """Wrap long lines, preserving the author's own line breaks."""
    out = []
    for line in text.split("\n"):
        while len(line) > width:
            cut = line.rfind(" ", 0, width)
            if cut <= 0:
                break
            out.append(line[:cut])
            line = line[cut + 1:]
        out.append(line)
    return "\n".join(out)


def _edge_color(label, style):
    if style == "dotted":
        return EDGE_DOTTED
    if label:
        lowered = label.strip().lower()
        if lowered in _YES_LABELS:
            return EDGE_YES
        if lowered in _NO_LABELS:
            return EDGE_NO
    return EDGE_DEFAULT


class MermaidGraphView(ida_graph.GraphViewer):
    """Renders one parsed FlowGraph in its own IDA graph tab."""

    def __init__(self, title, flow, func_ea=BADADDR, show_edge_labels=True):
        ida_graph.GraphViewer.__init__(self, title, close_open=True)
        self.flow = flow
        self.func_ea = func_ea
        self.show_edge_labels = show_edge_labels

        self._keys = []          # graph node id -> mermaid node key
        self._targets = {}       # graph node id -> resolved ea
        self._why = {}           # graph node id -> what matched, for the hint
        self._edge_labels = {}   # (src_id, dst_id) -> label
        self.linked_count = 0

    # -- graph construction ------------------------------------------------

    def OnRefresh(self):
        self.Clear()
        self._keys = []
        self._targets = {}
        self._why = {}
        self._edge_labels = {}
        self.linked_count = 0

        ids = {}
        for node in self.flow.ordered_nodes():
            node_id = self.AddNode(node.key)
            ids[node.key] = node_id
            self._keys.append(node.key)

            ea, why = resolve_target(node)
            self._targets[node_id] = ea
            self._why[node_id] = why
            if ea != BADADDR:
                self.linked_count += 1

        for edge in self.flow.edges:
            src, dst = ids.get(edge.src), ids.get(edge.dst)
            if src is None or dst is None:
                continue
            self.AddEdge(src, dst)
            if edge.label:
                self._edge_labels[(src, dst)] = edge.label

        return True

    def Show(self):
        shown = ida_graph.GraphViewer.Show(self)
        if shown:
            self._apply_edge_colors()
        return shown

    def _apply_edge_colors(self):
        """Colour-code edges -- the only channel left once labels are out."""
        widget = self.GetWidget()
        if widget is None:
            return
        try:
            viewer = ida_graph.get_graph_viewer(widget)
            graph = ida_graph.get_viewer_graph(viewer)
        except Exception as exc:
            msg("edge colouring unavailable: %s" % exc)
            return
        if graph is None:
            return

        ids = self.flow.index_of()
        for edge in self.flow.edges:
            src, dst = ids.get(edge.src), ids.get(edge.dst)
            if src is None or dst is None:
                continue
            color = _edge_color(edge.label, edge.style)
            if color == EDGE_DEFAULT:
                continue
            try:
                info = ida_graph.edge_info_t()
                info.color = color
                info.width = 1
                graph.set_edge(ida_graph.edge_t(src, dst), info)
            except Exception as exc:
                msg("edge %d->%d colouring failed: %s" % (src, dst, exc))
                return

    # -- appearance --------------------------------------------------------

    def _node_color(self, node, node_id):
        if self._targets.get(node_id, BADADDR) != BADADDR:
            return COLOR_LINKED
        if node.is_decision:
            return COLOR_DECISION
        if self._is_failure_node(node.key):
            return COLOR_FAILURE
        if not any(e.src == node.key for e in self.flow.edges):
            return COLOR_TERMINAL
        return COLOR_STEP

    def _is_failure_node(self, key):
        incoming = [e for e in self.flow.edges if e.dst == key]
        if not incoming:
            return False
        return all((e.label or "").strip().lower() in _NO_LABELS
                   for e in incoming)

    def OnGetText(self, node_id):
        key = self._keys[node_id]
        node = self.flow.nodes[key]

        lines = []
        if self.show_edge_labels:
            # IDA cannot draw a label on an edge, so an incoming Yes/No is
            # shown on the node it leads to: `[No]` above "Return failure".
            incoming = sorted({
                label for (src, dst), label in self._edge_labels.items()
                if dst == node_id
            })
            if incoming:
                lines.append("[%s]" % " / ".join(incoming))

        marker = "<> " if node.is_decision else ""
        lines.append(marker + _wrap(node.label))

        ea = self._targets.get(node_id, BADADDR)
        if ea != BADADDR:
            lines.append(ea_str(ea))

        return ("\n".join(lines), self._node_color(node, node_id))

    def OnHint(self, node_id):
        key = self._keys[node_id]
        node = self.flow.nodes[key]
        ea = self._targets.get(node_id, BADADDR)

        parts = ["%s: %s" % (key, node.label.replace("\n", " "))]
        parts.append("shape: %s" % node.shape)
        if node.target:
            parts.append("click target: %s" % node.target)
        if ea != BADADDR:
            name = ida_funcs.get_func_name(ea) or ida_name.get_name(ea)
            parts.append("links to %s (%s)" % (ea_str(ea), name or "?"))
            # Say which of the four passes matched: a link found by a single
            # token is a guess, and the reader deserves to see that it was one.
            parts.append("matched by %s" % (self._why.get(node_id) or "?"))
            parts.append("double-click to jump")
        return "\n".join(parts)

    def OnEdgeHint(self, src, dst):
        """The only place a Mermaid edge label survives verbatim."""
        return self._edge_labels.get((src, dst))

    # -- interaction -------------------------------------------------------

    def OnDblClick(self, node_id):
        ea = self._targets.get(node_id, BADADDR)
        if ea == BADADDR:
            key = self._keys[node_id]
            msg("node %s has no address to jump to "
                "(add `click %s \"name-or-0xaddr\"` to the source)" % (key, key))
            return True
        ida_kernwin.jumpto(ea)
        return True

    def OnClose(self):
        pass


def build_title(func_ea):
    """Tab title. Per-function, so two functions' graphs coexist."""
    if func_ea == BADADDR:
        return "Mermaid flowchart"
    name = ida_funcs.get_func_name(func_ea) or ea_str(func_ea)
    return "Flowchart: %s" % name


def show(source, func_ea=BADADDR, show_edge_labels=True):
    """Parse `source` and display it. Returns the viewer, or None on failure."""
    flow = parser.parse(source)
    for warning in flow.warnings:
        msg("parser: %s" % warning)

    if not flow.nodes:
        ida_kernwin.warning(
            "No nodes found in that flowchart.\n\n"
            "Expected Mermaid flowchart syntax, for example:\n"
            "  flowchart TD\n"
            "      A[\"start\"] --> B[\"next\"]"
        )
        return None

    viewer = MermaidGraphView(build_title(func_ea), flow, func_ea, show_edge_labels)
    if not viewer.Show():
        msg("failed to open the graph window.")
        return None

    msg("%s: %d nodes, %d edges, %d linked to addresses."
        % (build_title(func_ea), len(flow.nodes), len(flow.edges),
           viewer.linked_count))
    return viewer
