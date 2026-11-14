"""Go verified-edge extractor tests (R2.4).

Every expected graph is an INDEPENDENT hand-authored expectation -- the
tests never validate the extractor against its own output. ALL fixtures
are SYNTHETIC (labelled); real-corpus validation (crAPI, wrongsecrets
go.mod/go.sum envelopes) runs through tools/oracle_go.py and is recorded
in the R2_4 delivery report. No `go` CLI exists in this environment, so
`go mod graph` real-evidence generation is NOT possible (GAP-R2-08);
graph-file fixtures are synthetic and disclosed as such.

Evidence tiers (approved R2.4 scope):
- go-mod-graph.txt  (go mod graph output)  -> resolved parent-child edges
  (VERIFIED when both module@version identities parse; the graph IS the
  resolved evidence);
- go.mod            -> direct/indirect require declarations + replace
  directives tallied and disclosed, NEVER edges (parent = the main module,
  which is not a lockfile component; manifest declarations are not
  relationships);
- go.sum            -> checksum list: membership only, NEVER edges.

Scenario classes: direct, transitive chains, multiple parents, multiple
versions, major-version suffixes (/v2), replacements (incl. local),
+incompatible versions, Go path escaping, missing versions, malformed
files, unsupported files, duplicate records, dispatch, determinism,
vocabulary. Go has no peer/optional/dev mechanism in lock evidence --
the closest analogues (indirect markers, replace aliases) are tested
explicitly and the mapping is disclosed.
"""

import pytest

from analysis.lock_graph import contract
from analysis.lock_graph import registry


def _write(tmp_path, text, name):
    lock = tmp_path / name
    lock.write_text(text, encoding="utf-8")
    return str(lock)


def _verified_pairs(result):
    return {(e["parent_name"], e["parent_version"],
             e["child_name"], e["child_version"])
            for e in result["edges"] if e["confidence"] == "VERIFIED"}


# -- go mod graph: resolved edges ---------------------------------------------
GRAPH = """\
github.com/acme/app@v1.0.0 github.com/gin-gonic/gin@v1.9.0
github.com/gin-gonic/gin@v1.9.0 github.com/golang/protobuf@v1.3.3
github.com/golang/protobuf@v1.3.3 google.golang.org/protobuf@v1.26.0
google.golang.org/protobuf@v1.26.0 github.com/google/go-cmp@v0.5.5
"""


def test_graph_chain_verified_edges(tmp_path):
    # SYNTHETIC: alpha->beta->gamma->delta resolved chain
    result = registry.extract_for_file(
        _write(tmp_path, GRAPH, "go-mod-graph.txt"))
    assert result["engine"] == "GO_MOD_GRAPH_V1"
    assert result["graph_status"] == "VERIFIED_EDGES_AVAILABLE"
    assert _verified_pairs(result) == {
        ("github.com/acme/app", "v1.0.0",
         "github.com/gin-gonic/gin", "v1.9.0"),
        ("github.com/gin-gonic/gin", "v1.9.0",
         "github.com/golang/protobuf", "v1.3.3"),
        ("github.com/golang/protobuf", "v1.3.3",
         "google.golang.org/protobuf", "v1.26.0"),
        ("google.golang.org/protobuf", "v1.26.0",
         "github.com/google/go-cmp", "v0.5.5"),
    }
    edge = next(e for e in result["edges"]
                if e["child_name"] == "github.com/golang/protobuf")
    assert edge["ecosystem"] == "golang"
    assert edge["parent_purl"].startswith("pkg:golang/github.com/")
    assert edge["fingerprint"].startswith("sha256:")
    assert edge["evidence_source"] == "GO_MODULE_GRAPH"


def test_graph_multiple_parents_and_versions(tmp_path):
    # SYNTHETIC: two parents on the same child; one child at two versions
    graph = (
        "app.example/a@v1.0.0 shared.example/lib@v1.2.0\n"
        "app.example/b@v2.0.0 shared.example/lib@v1.2.0\n"
        "app.example/a@v1.0.0 shared.example/lib@v2.0.0\n"
    )
    result = registry.extract_for_file(
        _write(tmp_path, graph, "go-mod-graph.txt"))
    pairs = _verified_pairs(result)
    assert ("app.example/a", "v1.0.0", "shared.example/lib", "v1.2.0") \
        in pairs
    assert ("app.example/b", "v2.0.0", "shared.example/lib", "v1.2.0") \
        in pairs
    assert ("app.example/a", "v1.0.0", "shared.example/lib", "v2.0.0") \
        in pairs


def test_graph_major_version_suffix_and_incompatible(tmp_path):
    # SYNTHETIC: /v2 major-version suffix and +incompatible versions are
    # preserved verbatim as identity components
    graph = (
        "app.example/m@v1.0.0 app.example/thing/v2@v2.3.0\n"
        "app.example/m@v1.0.0 legacy.example/old@v1.0.0+incompatible\n"
    )
    result = registry.extract_for_file(
        _write(tmp_path, graph, "go-mod-graph.txt"))
    pairs = _verified_pairs(result)
    assert ("app.example/m", "v1.0.0",
            "app.example/thing/v2", "v2.3.0") in pairs
    edge = next(e for e in result["edges"]
                if e["child_name"] == "legacy.example/old")
    assert edge["child_version"] == "v1.0.0+incompatible"


def test_graph_escaped_module_paths_decoded(tmp_path):
    # REAL corpus shape (go mod graph prints Go's escaped module paths):
    # uppercase letters appear as !x; the canonical identity decodes them
    graph = (
        "app.example/m@v1.0.0 github.com/!burnt!sushi/toml@v0.3.1\n"
    )
    result = registry.extract_for_file(
        _write(tmp_path, graph, "go-mod-graph.txt"))
    pairs = _verified_pairs(result)
    assert pairs == {
        ("app.example/m", "v1.0.0",
         "github.com/BurntSushi/toml", "v0.3.1")}


def test_graph_missing_version_unresolved(tmp_path):
    # SYNTHETIC: a line whose child has no version can never be VERIFIED
    graph = "app.example/m@v1.0.0 broken.example/lib\n"
    result = registry.extract_for_file(
        _write(tmp_path, graph, "go-mod-graph.txt"))
    assert _verified_pairs(result) == set()
    edge = result["edges"][0]
    assert edge["confidence"] == "UNRESOLVED"
    assert edge["resolution_status"] == "MALFORMED_GRAPH_LINE"


def test_graph_malformed_lines_counted(tmp_path):
    # SYNTHETIC: garbage lines count as invalid; valid lines still extract
    graph = (
        "not-a-graph-line\n"
        "only.one@v1.0.0\n"
        "app.example/m@v1.0.0 other.example/n@v2.0.0\n"
        "a@v1 b@v2 c@v3\n"
    )
    result = registry.extract_for_file(
        _write(tmp_path, graph, "go-mod-graph.txt"))
    assert result["tallies"]["invalid_records"] == 3
    assert _verified_pairs(result) == {
        ("app.example/m", "v1.0.0", "other.example/n", "v2.0.0")}


def test_graph_duplicate_lines_dedupe_with_tally(tmp_path):
    # SYNTHETIC: identical resolved edge lines dedupe; count disclosed
    graph = (
        "app.example/m@v1.0.0 lib.example/x@v2.0.0\n"
        "app.example/m@v1.0.0 lib.example/x@v2.0.0\n"
    )
    result = registry.extract_for_file(
        _write(tmp_path, graph, "go-mod-graph.txt"))
    assert len(_verified_pairs(result)) == 1
    assert result["tallies"]["duplicate_records_dropped"] == 1


def test_graph_exact_instance_semantics_never_ambiguous(tmp_path):
    # go mod graph lines are instance-to-instance resolved pairs: the
    # ambiguity machinery used by constraint-range lockfiles cannot arise
    result = registry.extract_for_file(
        _write(tmp_path, GRAPH, "go-mod-graph.txt"))
    assert all(e["confidence"] != contract.AMBIGUOUS
               for e in result["edges"])


def test_graph_unsupported_file_envelope(tmp_path):
    result = registry.extract_for_file(
        _write(tmp_path, "this is not a graph\n", "go-mod-graph.txt"))
    assert result["graph_status"] == "NO_VERIFIED_EDGES"


# -- go.mod: declarations envelope ---------------------------------------------
GOMOD = """\
module app.example/m

go 1.21

require github.com/direct/one v1.2.3

require (
\tgithub.com/direct/two v2.0.0+incompatible
\tapp.example/thing/v2 v2.3.0
\tgithub.com/indirect/x v1.1.1 // indirect
\tgithub.com/indirect/y v0.0.0-20200101000000-abcdefabcdef // indirect
)

replace github.com/old/lib => github.com/new/lib v1.5.0

exclude github.com/bad/pkg v9.9.9
"""


def test_gomod_declarations_tallied_never_edges(tmp_path):
    # go.mod pins direct requires and indirect markers, but the parent is
    # the MAIN MODULE (not a lockfile component): declarations are
    # tallied and disclosed, no edges, no synthetic root
    result = registry.extract_for_file(_write(tmp_path, GOMOD, "go.mod"))
    assert result["engine"] == "GO_MOD_DECLARATIONS_V1"
    assert result["graph_status"] == "UNSUPPORTED_FORMAT"
    assert result["edges"] == []
    assert result["tallies"]["direct_declarations"] == 3
    assert result["tallies"]["indirect_declarations"] == 2
    assert result["tallies"]["replacements"] == 1
    assert result["membership_packages"] == 5


def test_gomod_replace_directive_disclosed_not_invented(tmp_path):
    # replace directives are dependency-substitution evidence, not
    # parent-child relationships: recorded verbatim in the disclosures
    result = registry.extract_for_file(_write(tmp_path, GOMOD, "go.mod"))
    disclosure = " ".join(result["limitations"])
    assert "replace directive" in disclosure
    assert "github.com/old/lib => github.com/new/lib v1.5.0" in disclosure


def test_gomod_local_replacement_disclosed(tmp_path):
    # SYNTHETIC: local (filesystem) replacement -- recorded, never a graph
    gomod = GOMOD.replace(
        "replace github.com/old/lib => github.com/new/lib v1.5.0",
        "replace github.com/old/lib => ../local/lib")
    result = registry.extract_for_file(_write(tmp_path, gomod, "go.mod"))
    disclosure = " ".join(result["limitations"])
    assert "github.com/old/lib => ../local/lib" in disclosure
    assert "[local filesystem path]" in disclosure


def test_gomod_not_a_gomod_file(tmp_path):
    result = registry.extract_for_file(
        _write(tmp_path, "just some text\n", "go.mod"))
    assert result["graph_status"] == "UNSUPPORTED_FORMAT"
    assert result["edges"] == []


# -- go.sum: membership envelope --------------------------------------------------
GOSUM = """\
github.com/outer/pkg v1.0.0 h1:AAA=
github.com/outer/pkg v1.0.0/go.mod h1:BBB=
github.com/inner/lib v2.0.0+incompatible h1:CCC=
github.com/inner/lib v2.0.0+incompatible/go.mod h1:DDD=
"""


def test_gosum_membership_only_never_edges(tmp_path):
    # go.sum is a checksum list: membership evidence, NEVER parent-child
    # relationships (approved R2.4 constraint)
    result = registry.extract_for_file(_write(tmp_path, GOSUM, "go.sum"))
    assert result["engine"] == "GO_SUM_MEMBERSHIP_V1"
    assert result["graph_status"] == "UNSUPPORTED_FORMAT"
    assert result["edges"] == []
    assert result["membership_packages"] == 2
    assert any("checksum" in line for line in result["limitations"])


def test_gosum_not_a_checksum_list(tmp_path):
    result = registry.extract_for_file(
        _write(tmp_path, "random content\n", "go.sum"))
    assert result["membership_packages"] == 0


# -- dispatch, determinism, vocabulary ---------------------------------------------
def test_registry_dispatches_go_evidence_files():
    assert {"go.mod", "go.sum", "go-mod-graph.txt"} <= \
        registry.LOCKFILE_NAMES


def test_run_to_run_determinism(tmp_path):
    a = registry.extract_for_file(
        _write(tmp_path, GRAPH, "go-mod-graph.txt"))
    b = registry.extract_for_file(
        _write(tmp_path, GRAPH, "go-mod-graph.txt"))
    assert a == b


def test_confidence_vocabulary_pinned(tmp_path):
    result = registry.extract_for_file(
        _write(tmp_path, GRAPH, "go-mod-graph.txt"))
    for edge in result["edges"]:
        assert edge["confidence"] in (
            contract.VERIFIED, contract.AMBIGUOUS, contract.UNRESOLVED,
            contract.UNSUPPORTED, contract.INVALID)
