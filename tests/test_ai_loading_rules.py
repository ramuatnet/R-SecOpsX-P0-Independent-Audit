"""Phase 6 — HF loading-pattern SAST rules (technique, no tool integration).

Two window rules added to ``REGEX_RULES`` (the same table as
``PYTHON_PICKLE_LOAD``), each encoding its kill inside the pattern so no
AST hook is needed:

* ``PYTHON_TORCH_LOAD_UNSAFE`` — ``torch.load(`` fires unless
  ``weights_only=True`` appears within 300 chars that NEVER cross another
  ``torch.load(`` (a tempered negative lookahead). The tempering is the
  whole point: a later safe call's guard must not leak backwards and
  silence an earlier vulnerable call, and an earlier guard must not kill
  a later unguarded call.
* ``PYTHON_TRANSFORMERS_REMOTE_CODE`` — ``trust_remote_code=True`` is
  code executed from the model repository's control sphere (CWE-94).
  ``=False`` never matches; the kwarg in a string or comment is
  suppressed by the shared comment/string guard.

Both are python-only: the same text in a non-python file must not fire.
"""
from __future__ import annotations

from pathlib import Path

from scanner.sast import scan_file

MY_RULES = {"PYTHON_TORCH_LOAD_UNSAFE", "PYTHON_TRANSFORMERS_REMOTE_CODE"}


def _hits(path: Path) -> list[dict]:
    return [f for f in scan_file(str(path)) if f["rule_id"] in MY_RULES]


# ---------------------------------------------------------------------------
# torch.load
# ---------------------------------------------------------------------------

def test_unguarded_torch_load_fires(tmp_path: Path):
    f = tmp_path / "load.py"
    f.write_text(
        "import torch\n"
        "\n"
        "def load(path):\n"
        "    return torch.load(path)\n", encoding="utf-8")
    hits = _hits(f)
    assert len(hits) == 1
    hit = hits[0]
    assert hit["rule_id"] == "PYTHON_TORCH_LOAD_UNSAFE"
    assert hit["severity"] == "Critical"
    assert hit["cwe"] == "CWE-502"
    assert hit["line"] == 4


def test_weights_only_true_kills_the_finding(tmp_path: Path):
    f = tmp_path / "load_safe.py"
    f.write_text(
        "import torch\n"
        "\n"
        "def load(path):\n"
        "    return torch.load(path, weights_only=True)\n", encoding="utf-8")
    assert _hits(f) == []


def test_weights_only_indented_or_spaced_still_kills(tmp_path: Path):
    f = tmp_path / "load_safe2.py"
    f.write_text(
        "import torch\n"
        "state = torch.load(open(p, 'rb'),\n"
        "                   weights_only = True)\n", encoding="utf-8")
    assert _hits(f) == []


def test_later_safe_call_does_not_kill_earlier_vulnerable_call(
        tmp_path: Path):
    # the regression the tempered token exists for: within 300 chars after
    # the vulnerable call sits a SAFE call -- the kill must not leak back
    f = tmp_path / "mixed.py"
    f.write_text(
        "import torch\n"
        "\n"
        "def a(p):\n"
        "    return torch.load(p)\n"
        "\n"
        "def b(p):\n"
        "    return torch.load(p, weights_only=True)\n", encoding="utf-8")
    hits = _hits(f)
    assert len(hits) == 1
    assert hits[0]["line"] == 4


def test_earlier_guard_does_not_kill_later_vulnerable_call(
        tmp_path: Path):
    f = tmp_path / "mixed2.py"
    f.write_text(
        "import torch\n"
        "\n"
        "def a(p):\n"
        "    return torch.load(p, weights_only=True)\n"
        "\n"
        "def b(p):\n"
        "    return torch.load(p)\n", encoding="utf-8")
    hits = _hits(f)
    assert len(hits) == 1
    assert hits[0]["line"] == 7


def test_weights_only_false_still_fires(tmp_path: Path):
    # weights_only=False re-enables full unpickling: finding stays
    f = tmp_path / "explicit_false.py"
    f.write_text(
        "import torch\n"
        "state = torch.load(p, weights_only=False)\n", encoding="utf-8")
    hits = _hits(f)
    assert len(hits) == 1


def test_torch_load_mention_in_a_comment_is_suppressed(tmp_path: Path):
    f = tmp_path / "commented.py"
    f.write_text(
        "import torch\n"
        "# state = torch.load(p)\n"
        "total = 0\n", encoding="utf-8")
    assert _hits(f) == []


# ---------------------------------------------------------------------------
# trust_remote_code
# ---------------------------------------------------------------------------

def test_trust_remote_code_true_fires(tmp_path: Path):
    f = tmp_path / "remote.py"
    f.write_text(
        "from transformers import AutoModel\n"
        "\n"
        "def build(name):\n"
        "    return AutoModel.from_pretrained(name, trust_remote_code=True)\n",
        encoding="utf-8")
    hits = _hits(f)
    assert len(hits) == 1
    hit = hits[0]
    assert hit["rule_id"] == "PYTHON_TRANSFORMERS_REMOTE_CODE"
    assert hit["severity"] == "High"
    assert hit["cwe"] == "CWE-94"
    assert hit["line"] == 4


def test_trust_remote_code_false_is_silent(tmp_path: Path):
    f = tmp_path / "remote_off.py"
    f.write_text(
        "from transformers import AutoModel\n"
        "\n"
        "def build(name):\n"
        "    return AutoModel.from_pretrained(name, trust_remote_code=False)\n",
        encoding="utf-8")
    assert _hits(f) == []


def test_trust_remote_code_indirection_is_an_honest_gap(tmp_path: Path):
    # a variable value is not a literal True: unproven, not guessed
    f = tmp_path / "indirect.py"
    f.write_text(
        "from transformers import AutoModel\n"
        "\n"
        "def build(name, trust):\n"
        "    return AutoModel.from_pretrained(name,\n"
        "                                     trust_remote_code=trust)\n",
        encoding="utf-8")
    assert _hits(f) == []


def test_trust_remote_code_in_a_docstring_is_suppressed(tmp_path: Path):
    f = tmp_path / "doc.py"
    f.write_text(
        '"""Example: from_pretrained(name, trust_remote_code=True)."""\n'
        "from transformers import AutoModel\n"
        "x = 1\n", encoding="utf-8")
    assert _hits(f) == []


# ---------------------------------------------------------------------------
# language gate
# ---------------------------------------------------------------------------

def test_same_text_in_a_non_python_file_does_not_fire(tmp_path: Path):
    f = tmp_path / "remote.js"
    f.write_text(
        "const a = 'trust_remote_code=True';\n"
        "const b = 'torch.load(path)';\n", encoding="utf-8")
    assert _hits(f) == []


def test_corpus_vulnerable_loading_fixture_has_exactly_two_hits():
    # the labelled corpus fixture must produce exactly the two findings
    # its ground truth declares, and nothing else from these rules
    fixture = Path("tests/vuln-test-corpus/ai_ml/vulnerable_loading.py")
    hits = _hits(fixture)
    assert {h["rule_id"] for h in hits} == MY_RULES
    assert sorted(h["line"] for h in hits) == [14, 19]


def test_corpus_safe_loading_fixture_is_clean():
    fixture = Path("tests/vuln-test-corpus/ai_ml/safe_loading.py")
    assert _hits(fixture) == []
