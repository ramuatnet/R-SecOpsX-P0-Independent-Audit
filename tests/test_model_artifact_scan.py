"""Phase 6 — native model-artifact scanner (pickle opcode + safetensors).

Technique extracted from PickleScan/Fickling and the safetensors format
spec, reimplemented stdlib-only in ``scanner/model_artifact.py``. The
contract this file pins:

* NEVER EXECUTE — the scanner disassembles with ``pickletools.genops``;
  no ``pickle.load`` runs anywhere in the path. The fixtures here are
  BUILT with ``pickle.dumps`` (dumping never executes ``__reduce__``
  results), and the tests assert findings without ever loading them.
* DANGEROUS GLOBALS are found in every shape the technique covers:
  protocol-2 ``GLOBAL``, protocol-4 ``STACK_GLOBAL`` through the memo,
  unresolvable (``unknown``) stack globals, concatenated streams,
  torch-zip containers, magic-gated ``.bin``.
* SILENT ON THE BENIGN — plain data pickles, garbage with a pickle
  extension, non-pickle ``.bin``, directories excluded by policy: no
  finding, no crash.
* safetensors structure — header past EOF, overflow/overlap/negative
  offsets, dangling payload bytes, header over the 100 MB spec cap.
* DIRECTORY ADVISORY — pickle weights next to a model-shaped
  ``config.json`` with no ``.safetensors`` sibling; suppressed when the
  sibling exists or the config is not model-shaped.
* ESCAPE HATCHES — ``RSX_MODEL_ARTIFACT_SCAN=0`` disables the pass;
  ``RSX_ARTIFACT_STRICT=1`` additionally reports unproven globals at Low.

No input may raise: every boundary (garbage, truncated, unreadable)
returns silently or with a finding, never an exception.
"""
from __future__ import annotations

import json
import pickle
import struct
import zipfile
from pathlib import Path

import pytest

from scanner.model_artifact import scan_model_artifacts
from scanner.sast import scan_directory


# ---------------------------------------------------------------------------
# Fixture builders — dump only, never loaded
# ---------------------------------------------------------------------------

class _EvilEval:
    """__reduce__ returns (eval, ...); pickle.dumps records it as the
    GLOBAL ``builtins eval``. Dumping writes opcodes — nothing executes."""

    def __reduce__(self):
        return (eval, ("__import__('os').system('x')",))


def _evil_payload(protocol: int = 4) -> bytes:
    return pickle.dumps(_EvilEval(), protocol=protocol)


def _silent_payload() -> bytes:
    return pickle.dumps({"weights": 1, "n": 3}, protocol=4)


def _write_safetensors(path: Path, header: dict | None = None,
                       payload: bytes = b"\x00" * 16,
                       declared_len: int | None = None,
                       raw_header: bytes | None = None) -> None:
    body = raw_header if raw_header is not None else json.dumps(header or {}).encode()
    length = len(body) if declared_len is None else declared_len
    path.write_bytes(struct.pack("<Q", length) + body + payload)


_VALID_ST_HEADER = {"t": {"dtype": "F32", "shape": [4],
                          "data_offsets": [0, 16]}}


# ---------------------------------------------------------------------------
# Layer 1 — pickle opcode extraction
# ---------------------------------------------------------------------------

def test_protocol4_stack_global_is_flagged(tmp_path: Path):
    f = tmp_path / "evil.pt"
    f.write_bytes(_evil_payload(4))
    findings = scan_model_artifacts(tmp_path)
    pickle_hits = [x for x in findings
                   if x["rule_id"] == "AI_PICKLE_DANGEROUS_GLOBAL"]
    assert len(pickle_hits) == 1
    hit = pickle_hits[0]
    assert "builtins.eval" in hit["snippet"]
    assert hit["severity"] == "Critical"
    assert hit["cwe"] == "CWE-502"
    assert hit["line"] == 1
    assert hit["file"].endswith("evil.pt")
    assert "pickle" in hit.get("detection", "").lower()


def test_protocol2_global_is_flagged(tmp_path: Path):
    # protocol 2 uses the GLOBAL opcode instead of STACK_GLOBAL+MEMOIZE,
    # and names the builtin with the Python-2-era module "__builtin__"
    f = tmp_path / "evil2.pkl"
    f.write_bytes(_evil_payload(2))
    findings = scan_model_artifacts(tmp_path)
    assert any(x["rule_id"] == "AI_PICKLE_DANGEROUS_GLOBAL"
               and "eval" in x["snippet"]
               and "__builtin__" in x["snippet"] for x in findings)


def test_unresolvable_stack_global_is_dangerous(tmp_path: Path):
    # crafted: STACK_GLOBAL whose name operand is an INT (evasion shape).
    # PROTO4, SHORT_BINUNICODE "os", BININT1 2, STACK_GLOBAL, STOP
    raw = b"\x80\x04" + b"\x8c\x02os" + b"K\x02" + b"\x93" + b"."
    (tmp_path / "unknown.pkl").write_bytes(raw)
    findings = scan_model_artifacts(tmp_path)
    assert any(x["rule_id"] == "AI_PICKLE_DANGEROUS_GLOBAL"
               and "unknown" in x["snippet"] for x in findings)


def test_innocuous_pickle_is_silent(tmp_path: Path):
    (tmp_path / "safe.pkl").write_bytes(_silent_payload())
    assert scan_model_artifacts(tmp_path) == []


def test_unlisted_module_global_is_silent_by_default(tmp_path: Path):
    # protocol-0 GLOBAL myorg myfunc -> suspicious, not dangerous -> silent
    (tmp_path / "odd.pkl").write_bytes(b"cmyorg\nmyfunc\n.")
    assert scan_model_artifacts(tmp_path) == []


def test_strict_mode_reports_unproven_global(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("RSX_ARTIFACT_STRICT", "1")
    (tmp_path / "odd.pkl").write_bytes(b"cmyorg\nmyfunc\n.")
    findings = scan_model_artifacts(tmp_path)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AI_PICKLE_DANGEROUS_GLOBAL"
    assert findings[0]["severity"] == "Low"
    assert "strict" in findings[0]["snippet"]


def test_garbage_with_pickle_extension_is_silent(tmp_path: Path):
    (tmp_path / "garbage.pkl").write_bytes(b"\x00\x01 not a pickle \xff" * 32)
    assert scan_model_artifacts(tmp_path) == []


def test_truncated_pickle_salvages_the_dangerous_global(tmp_path: Path):
    # a partial pickle still unpickles its prefix: the GLOBAL before the
    # truncation point must be reported
    (tmp_path / "trunc.pkl").write_bytes(_evil_payload(4)[:-3])
    findings = scan_model_artifacts(tmp_path)
    assert any(x["rule_id"] == "AI_PICKLE_DANGEROUS_GLOBAL"
               and "builtins.eval" in x["snippet"] for x in findings)


def test_concatenated_streams_are_all_parsed(tmp_path: Path):
    # torch checkpoints store several pickles concatenated after the magic
    stream = _silent_payload() + _evil_payload(4)
    (tmp_path / "concat.pkl").write_bytes(stream)
    findings = scan_model_artifacts(tmp_path)
    assert any(x["rule_id"] == "AI_PICKLE_DANGEROUS_GLOBAL" for x in findings)


def test_torch_zip_container_member_is_scanned(tmp_path: Path):
    zpath = tmp_path / "torchzip.pt"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("archive/data.pkl", _evil_payload(4))
        zf.writestr("archive/data/0", b"\x00" * 64)  # raw tensor, not a pickle
    findings = scan_model_artifacts(tmp_path)
    hits = [x for x in findings
            if x["rule_id"] == "AI_PICKLE_DANGEROUS_GLOBAL"]
    assert len(hits) == 1
    assert "archive/data.pkl" in hits[0]["snippet"]


def test_bin_is_magic_gated(tmp_path: Path):
    # pickle-magic .bin is a candidate; a generic binary stays silent
    (tmp_path / "pytorch_model.bin").write_bytes(_evil_payload(4))
    (tmp_path / "plain.bin").write_bytes(bytes(range(256)) * 8)
    findings = scan_model_artifacts(tmp_path)
    assert [x for x in findings if x["file"].endswith("plain.bin")] == []
    assert any(x["file"].endswith("pytorch_model.bin")
               and x["rule_id"] == "AI_PICKLE_DANGEROUS_GLOBAL"
               for x in findings)


def test_extension_outside_the_candidate_sets_is_not_scanned(tmp_path: Path):
    (tmp_path / "payload.txt").write_bytes(_evil_payload(4))
    assert scan_model_artifacts(tmp_path) == []


def test_excluded_directories_are_not_scanned(tmp_path: Path):
    hidden = tmp_path / "node_modules"
    hidden.mkdir()
    (hidden / "evil.pkl").write_bytes(_evil_payload(4))
    assert scan_model_artifacts(tmp_path) == []


def test_kill_switch_disables_the_pass(tmp_path: Path, monkeypatch):
    (tmp_path / "evil.pt").write_bytes(_evil_payload(4))
    (tmp_path / "bad.safetensors").write_bytes(struct.pack("<Q", 9_999) + b"{")
    assert scan_model_artifacts(tmp_path) != []
    monkeypatch.setenv("RSX_MODEL_ARTIFACT_SCAN", "0")
    assert scan_model_artifacts(tmp_path) == []


# ---------------------------------------------------------------------------
# Layer 2 — safetensors structure validation
# ---------------------------------------------------------------------------

def test_valid_safetensors_is_silent(tmp_path: Path):
    _write_safetensors(tmp_path / "valid.safetensors",
                       _VALID_ST_HEADER, payload=b"\x00" * 16)
    assert scan_model_artifacts(tmp_path) == []


def test_header_length_past_eof_is_flagged(tmp_path: Path):
    _write_safetensors(tmp_path / "eof.safetensors",
                       declared_len=10_000, raw_header=b'{"t":')
    findings = scan_model_artifacts(tmp_path)
    hits = [x for x in findings
            if x["rule_id"] == "AI_SAFETENSORS_INVALID_HEADER"]
    assert len(hits) == 1
    assert hits[0]["severity"] == "High"
    assert "past EOF" in hits[0]["snippet"]


def test_offset_beyond_payload_is_flagged(tmp_path: Path):
    header = {"t": {"dtype": "F32", "shape": [64], "data_offsets": [0, 256]}}
    _write_safetensors(tmp_path / "overflow.safetensors", header,
                       payload=b"\x00" * 16)
    findings = scan_model_artifacts(tmp_path)
    assert any(x["rule_id"] == "AI_SAFETENSORS_INVALID_HEADER"
               and "exceeds the payload" in x["snippet"]
               for x in findings)


def test_negative_offset_is_flagged(tmp_path: Path):
    header = {"t": {"dtype": "F32", "shape": [4], "data_offsets": [-8, 16]}}
    _write_safetensors(tmp_path / "neg.safetensors", header,
                       payload=b"\x00" * 16)
    findings = scan_model_artifacts(tmp_path)
    assert any(x["rule_id"] == "AI_SAFETENSORS_INVALID_HEADER"
               and "negative" in x["snippet"] for x in findings)


def test_overlapping_tensors_are_flagged(tmp_path: Path):
    header = {"a": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]},
              "b": {"dtype": "F32", "shape": [2], "data_offsets": [4, 12]}}
    _write_safetensors(tmp_path / "overlap.safetensors", header,
                       payload=b"\x00" * 12)
    findings = scan_model_artifacts(tmp_path)
    assert any(x["rule_id"] == "AI_SAFETENSORS_INVALID_HEADER"
               and "overlaps" in x["snippet"] for x in findings)


def test_dangling_payload_bytes_are_flagged(tmp_path: Path):
    header = {"t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}
    _write_safetensors(tmp_path / "dangling.safetensors", header,
                       payload=b"\x00" * 32)
    findings = scan_model_artifacts(tmp_path)
    assert any(x["rule_id"] == "AI_SAFETENSORS_INVALID_HEADER"
               and "not referenced" in x["snippet"] for x in findings)


def test_header_over_the_100mb_spec_cap_is_flagged(tmp_path: Path):
    # only the 8-byte length prefix exists on disk: the cap must be checked
    # BEFORE any attempt to read the declared header
    (tmp_path / "huge.safetensors").write_bytes(
        struct.pack("<Q", 101 * 1024 * 1024) + b"{}")
    findings = scan_model_artifacts(tmp_path)
    assert any(x["rule_id"] == "AI_SAFETENSORS_INVALID_HEADER"
               and "100 MB" in x["snippet"] for x in findings)


def test_non_json_header_is_flagged(tmp_path: Path):
    _write_safetensors(tmp_path / "notjson.safetensors",
                       raw_header=b"definitely not json!!")
    findings = scan_model_artifacts(tmp_path)
    assert any(x["rule_id"] == "AI_SAFETENSORS_INVALID_HEADER"
               and "not valid JSON" in x["snippet"] for x in findings)


# ---------------------------------------------------------------------------
# Layer 3 — directory-level advisory
# ---------------------------------------------------------------------------

def _model_dir(root: Path, name: str, model_config: dict,
               weights: bytes, with_safetensors: bool = False) -> Path:
    d = root / name
    d.mkdir()
    (d / "config.json").write_text(json.dumps(model_config), encoding="utf-8")
    (d / "pytorch_model.bin").write_bytes(weights)
    if with_safetensors:
        _write_safetensors(d / "model.safetensors", _VALID_ST_HEADER)
    return d


def test_pickle_weights_without_safetensors_raise_advisory(tmp_path: Path):
    _model_dir(tmp_path, "md", {"model_type": "bert"}, _silent_payload())
    findings = scan_model_artifacts(tmp_path)
    hits = [x for x in findings
            if x["rule_id"] == "AI_PICKLE_WEIGHTS_NO_SAFETENSORS"]
    assert len(hits) == 1
    assert hits[0]["severity"] == "Low"
    assert hits[0]["file"].endswith("pytorch_model.bin")


def test_safetensors_sibling_suppresses_the_advisory(tmp_path: Path):
    _model_dir(tmp_path, "md", {"model_type": "gpt2"}, _silent_payload(),
               with_safetensors=True)
    findings = scan_model_artifacts(tmp_path)
    assert [x for x in findings
            if x["rule_id"] == "AI_PICKLE_WEIGHTS_NO_SAFETENSORS"] == []


def test_non_model_config_json_raises_no_advisory(tmp_path: Path):
    # a config.json that is not model-shaped must not classify the dir
    _model_dir(tmp_path, "md", {"name": "something"}, _silent_payload())
    findings = scan_model_artifacts(tmp_path)
    assert [x for x in findings
            if x["rule_id"] == "AI_PICKLE_WEIGHTS_NO_SAFETENSORS"] == []


def test_advisory_needs_a_genuinely_pickle_weights_file(tmp_path: Path):
    # .bin that is not a pickle (no magic, not a zip) -> no advisory
    _model_dir(tmp_path, "md", {"model_type": "vit"},
               bytes(range(64)) * 4)
    findings = scan_model_artifacts(tmp_path)
    assert [x for x in findings
            if x["rule_id"] == "AI_PICKLE_WEIGHTS_NO_SAFETENSORS"] == []


# ---------------------------------------------------------------------------
# Layer 4 — engine wiring through scan_directory
# ---------------------------------------------------------------------------

def test_scan_directory_emits_artifact_findings(tmp_path: Path):
    (tmp_path / "evil.ckpt").write_bytes(_evil_payload(4))
    findings = scan_directory(str(tmp_path), workers=1)
    hits = [x for x in findings
            if x["rule_id"] == "AI_PICKLE_DANGEROUS_GLOBAL"]
    assert len(hits) == 1
    # group_findings rebuilds the representative with a fixed key set:
    # "snippet" is the evidence the normalizer consumes (normalize.py
    # _first(snippet, evidence, title)), so the shape contract is snippet.
    for key in ("rule_id", "title", "severity", "cwe", "file", "line",
                "snippet", "vuln_type", "remediation"):
        assert key in hits[0], f"missing {key} in {sorted(hits[0])}"
    assert "builtins.eval" in hits[0]["snippet"]
    assert hits[0]["line"] == 1
    assert hits[0]["file"].endswith("evil.ckpt")


def test_scan_directory_kill_switch_leaves_other_engines_intact(
        tmp_path: Path, monkeypatch):
    (tmp_path / "evil.ckpt").write_bytes(_evil_payload(4))
    # a normal text finding alongside: kill switch must not remove it
    (tmp_path / "app.py").write_text(
        "import pickle\n"
        "def load(f):\n"
        "    return pickle.load(f)\n", encoding="utf-8")
    monkeypatch.setenv("RSX_MODEL_ARTIFACT_SCAN", "0")
    findings = scan_directory(str(tmp_path), workers=1)
    assert [x for x in findings
            if x["rule_id"] == "AI_PICKLE_DANGEROUS_GLOBAL"] == []
    assert any(x["rule_id"] == "PYTHON_PICKLE_LOAD" for x in findings)


@pytest.mark.parametrize("ext", [".pkl", ".pickle", ".joblib", ".pt",
                                 ".pth", ".ckpt"])
def test_every_candidate_extension_is_scanned(tmp_path: Path,
                                              ext: str):
    (tmp_path / f"weights{ext}").write_bytes(_evil_payload(4))
    findings = scan_model_artifacts(tmp_path)
    assert any(x["rule_id"] == "AI_PICKLE_DANGEROUS_GLOBAL"
               for x in findings)
