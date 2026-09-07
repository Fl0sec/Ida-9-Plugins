"""Tests for the Mermaid subset parser.

The parser is the only part of this plugin that runs outside IDA, so it is the
only part that can be genuinely tested. Run it directly:

    python mermaid-flow/tests/test_parser.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mermaidflow import parser  # noqa: E402


HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLE = os.path.join(HERE, "example_driver.mmd")

_failures = []


def check(condition, description):
    if condition:
        print("  ok   %s" % description)
    else:
        print("  FAIL %s" % description)
        _failures.append(description)


def edge(graph, src, dst):
    for candidate in graph.edges:
        if candidate.src == src and candidate.dst == dst:
            return candidate
    return None


def test_real_example():
    print("real driver flowchart")
    with open(EXAMPLE, "r", encoding="utf-8") as handle:
        graph = parser.parse(handle.read())

    check(len(graph.nodes) == 31, "31 nodes (got %d)" % len(graph.nodes))
    check(len(graph.edges) == 32, "32 edges (got %d)" % len(graph.edges))
    check(graph.direction == "TD", "direction TD")

    # `F` is used bare in `E1 --> F` before `F["Create Device/TBMKEv1"]`
    # declares it: the late label must win over the placeholder.
    check(graph.nodes["F"].label == "Create Device/TBMKEv1",
          "forward-referenced node picks up its later label")

    check(graph.nodes["C"].label == "Initialize protection lock\nand worker stop event",
          "<br/> becomes a newline")
    check(graph.nodes["G"].is_decision, "{...} is a decision node")
    check(not graph.nodes["A"].is_decision, "[...] is not a decision node")

    check(edge(graph, "G", "X1").label == "No", "`-- No -->` label captured")
    check(edge(graph, "G", "H").label == "Yes", "`-- Yes -->` label captured")

    # `K --> L` and `K -. "failure is non-fatal" .-> L` are two Mermaid arrows
    # between the same pair; IDA would overdraw them, so they merge.
    merged = edge(graph, "K", "L")
    check(merged.style == "dotted", "duplicate edge keeps the dotted style")
    check(merged.label == "failure is non-fatal", "duplicate edge keeps the label")
    check(len([e for e in graph.edges if e.src == "K" and e.dst == "L"]) == 1,
          "duplicate edge collapsed to one")

    check(all(w.startswith("merged duplicate edge") for w in graph.warnings),
          "no unexpected warnings (%r)" % graph.warnings)


def test_link_forms():
    print("link forms")
    graph = parser.parse("""
        flowchart TD
        A --> B
        B --- C
        C -.-> D
        D ==> E
        E -->|piped| F
        F -- middle --> G
        G -. dotted label .-> H
        H == thick label ==> I
    """)
    check(edge(graph, "A", "B").style == "solid", "--> solid")
    check(edge(graph, "B", "C").style == "solid", "--- open link")
    check(edge(graph, "C", "D").style == "dotted", "-.-> dotted")
    check(edge(graph, "D", "E").style == "thick", "==> thick")
    check(edge(graph, "E", "F").label == "piped", "-->|label| captured")
    check(edge(graph, "F", "G").label == "middle", "-- label --> captured")
    check(edge(graph, "G", "H").label == "dotted label", "-. label .-> captured")
    check(edge(graph, "H", "I").label == "thick label", "== label ==> captured")


def test_shapes():
    print("shapes")
    graph = parser.parse("""
        flowchart TD
        A[rect] --> B(round)
        B --> C{decision}
        C --> D((circle))
        D --> E[[subroutine]]
        E --> F[(cylinder)]
        F --> G([stadium])
        G --> H{{hexagon}}
    """)
    expected = {
        "A": "rect", "B": "round", "C": "decision", "D": "circle",
        "E": "subroutine", "F": "cylinder", "G": "stadium", "H": "hexagon",
    }
    for key, shape in expected.items():
        check(graph.nodes[key].shape == shape,
              "%s -> %s (got %s)" % (key, shape, graph.nodes[key].shape))
    check(graph.nodes["H"].is_decision, "hexagon counts as a decision")


def test_chains_and_labels():
    print("chains, quoting and entities")
    graph = parser.parse("""
        flowchart LR
        A["one"] --> B["two"] --> C["three"]
        D["say &quot;hi&quot;"] --> E["a &amp; b"]
    """)
    check(edge(graph, "A", "B") is not None and edge(graph, "B", "C") is not None,
          "three-node chain in one statement")
    check(graph.nodes["D"].label == 'say "hi"', "&quot; decoded")
    check(graph.nodes["E"].label == "a & b", "&amp; decoded")
    check(any("direction LR ignored" in w for w in graph.warnings),
          "LR direction warned about")


def test_arrow_inside_label():
    print("arrow inside a label")
    graph = parser.parse('flowchart TD\nA["step a --> b"] --> B["done"]')
    check(len(graph.nodes) == 2, "label containing --> does not split the node")
    check(graph.nodes["A"].label == "step a --> b", "label text preserved")
    check(len(graph.edges) == 1, "exactly one edge")


def test_click_targets():
    print("click directives")
    graph = parser.parse("""
        flowchart TD
        A["RealDriverEntry"] --> B["helper"]
        click A "0x140001A90"
        click B href "SomeFunction"
    """)
    check(graph.nodes["A"].target == "0x140001A90", "click with bare target")
    check(graph.nodes["B"].target == "SomeFunction", "click with href target")


def test_tolerates_junk():
    print("tolerance")
    graph = parser.parse("""
        %%{init: {'theme':'dark'}}%%
        flowchart TD
        %% a comment
        subgraph Setup
        A --> B
        end
        classDef red fill:#f00
        class A red
        style B fill:#0f0
        linkStyle 0 stroke:#333
        A --> C;
    """)
    check(len(graph.nodes) == 3, "subgraph flattened, nodes kept (got %d)"
          % len(graph.nodes))
    check(any("subgraph flattened" in w for w in graph.warnings),
          "subgraph flattening reported")
    check(edge(graph, "A", "C") is not None, "`;`-terminated statement parsed")
    check(not any("ignored line" in w for w in graph.warnings),
          "presentational directives silently ignored (%r)" % graph.warnings)


def test_empty_and_garbage():
    print("degenerate input")
    check(parser.parse("").warnings, "empty input warns instead of raising")
    graph = parser.parse("this is not a flowchart at all")
    check(isinstance(graph.nodes, dict), "garbage input still returns a graph")


def main():
    for test in (test_real_example, test_link_forms, test_shapes,
                 test_chains_and_labels, test_arrow_inside_label,
                 test_click_targets, test_tolerates_junk, test_empty_and_garbage):
        test()
    print()
    if _failures:
        print("FAILED: %d check(s)" % len(_failures))
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
