"""--no-pdf must actually skip PDF generation. --no-excel already did.

THE DEFECT
----------
main.py declared `--no-pdf` at line 2526 and referenced it nowhere in the file.
`--no-excel`, declared on the adjacent line, was honoured at main.py:5016 as
`if not args.no_excel:`. The two render-skipping flags were therefore asymmetric:
one worked and one was inert, and the inert one was the one that mattered.

Verified by execution, not by reading source. A probe scan of a small directory
with --no-pdf still wrote Security_Report.pdf (64,468 bytes) and
Security_Executive_Report.pdf (56,867 bytes).

Why it mattered concretely: both large AI-corpus projects timed out in
'Generating PDF report', which was the only thing left between them and a quotable
artifact. llama_index-main spent 770.4s of its 3,600s budget on detection phases
and roughly 2,800s rendering a PDF that the benchmark harness never reads -- it
summarises from clean_report.json, written at main.py:4868, before that block.

The comment already in main.py below that block states the consequence precisely:
"A reader cannot tell a report that has no PDF from one where none was asked for."
That ambiguity was unresolvable while the "asked for" path was dead.

HOW IT IS TESTED
----------------
By running the scanner, because the failure mode is a flag that parses cleanly and
does nothing -- no amount of reading main.py distinguishes that from working code.
Both directions are asserted: --no-pdf must produce no PDF, and a default run must
still produce both PDFs. Asserting only the first would pass against a fix that
suppressed PDF generation unconditionally, which is a worse defect than the one
being fixed.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
MAIN = REPO / "main.py"
SRC = MAIN.read_text(encoding="utf-8")

# A minimal target, big enough to produce a non-empty report without being slow.
PROBE = """
import pickle
import subprocess

def run(cmd):
    return pickle.loads(cmd)

def shell(cmd):
    return subprocess.call(cmd, shell=True)
"""


@pytest.fixture(scope="module")
def probe_target(tmp_path_factory):
    d = tmp_path_factory.mktemp("nopdf_target")
    (d / "app.py").write_text(PROBE, encoding="utf-8")
    return d


def _scan(target: pathlib.Path, out: pathlib.Path, *extra: str) -> list[str]:
    proc = subprocess.run(
        [sys.executable, str(MAIN), str(target), "--output", str(out), *extra],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(REPO), timeout=900,
    )
    assert proc.returncode == 0, f"scan failed: {proc.stdout[-800:]}{proc.stderr[-800:]}"
    return sorted(p.name for p in out.glob("*.pdf"))


# ------------------------------------------------------------ static checks --

def test_the_flag_is_actually_consulted():
    """The one-line root cause. Declared, parsed, and never referenced."""
    assert "--no-pdf" in SRC, "the flag should still be declared"
    assert "args.no_pdf" in SRC, (
        "--no-pdf is declared and parsed but never consulted, so it skips nothing")


def test_no_pdf_and_no_excel_are_both_honoured():
    """The asymmetry this closed.

    The declaration is `parser.add_argument("--no-pdf", ...)` and never mentions
    `args.no_pdf`; only a guard does. So the defect condition is ZERO references,
    not one -- `--no-excel` has exactly one and is correct.
    """
    for flag in ("no_pdf", "no_excel"):
        assert SRC.count(f"args.{flag}") >= 1, (
            f"args.{flag} is never referenced, so --{'no-pdf' if flag == 'no_pdf' else 'no-excel'}"
            f" is declared, parsed and ignored")


def test_the_guard_covers_the_executive_pdf_too():
    """Guarding only the main PDF would leave the same ambiguity, smaller."""
    # Anchor on the PDF-generation guard itself. A bare find() of
    # "if not args.no_pdf:" hits an earlier guard that only wraps a console
    # step label ("Git diff / change intelligence"), and the 2400-char window
    # from there is an implicit, brittle distance budget -- adding any export
    # step before the PDF block pushes generate_pdf_report() out of it.
    i = SRC.find('if not args.no_pdf:\n        _step("Generating PDF report")')
    assert i != -1, "could not locate the PDF-generation guard"
    guarded = SRC[i:i + 2400]
    assert "generate_pdf_report(" in guarded
    assert "generate_executive_pdf_report(" in guarded, (
        "the executive PDF renders inside the same block; if the guard ended before "
        "it, --no-pdf would skip one document and still emit the other")


def test_the_flag_carries_help_text():
    """It had none, which is part of why an inert flag went unnoticed."""
    i = SRC.find('"--no-pdf", action="store_true"')
    assert i != -1, "could not locate the --no-pdf declaration"
    window = SRC[i:i + 400]
    assert "help=" in window, (
        "--no-pdf is declared with no help text, so --help could not tell a reader "
        "that it skips nothing")


# ------------------------------------------------------- behavioural checks --

def test_no_pdf_produces_no_pdf_but_still_writes_the_json(probe_target, tmp_path):
    out = tmp_path / "skip"
    pdfs = _scan(probe_target, out, "--no-pdf")
    assert pdfs == [], f"--no-pdf still rendered {pdfs}"
    assert (out / "clean_report.json").exists(), (
        "clean_report.json must still be written: it is written before PDF "
        "generation, and it is the artifact the benchmark harness reads")


def test_a_default_run_still_renders_both_pdfs(probe_target, tmp_path):
    """The direction that would catch an over-broad fix.

    A guard placed wrongly -- or one that skips rendering unconditionally -- passes
    the test above while breaking every normal scan. This asserts the default path
    is untouched.
    """
    out = tmp_path / "default"
    pdfs = _scan(probe_target, out)
    assert "Security_Report.pdf" in pdfs, f"default run produced {pdfs}"
    assert "Security_Executive_Report.pdf" in pdfs, f"default run produced {pdfs}"
    assert (out / "clean_report.json").exists()


def test_the_other_artifacts_are_unaffected_by_no_pdf(probe_target, tmp_path):
    """Skipping PDFs must not skip the SBOM, QBOM or scan-performance outputs.

    The corpus measures AI mapping and crypto inventory, which come from these. A
    flag meant to skip one document must not quietly drop the artifacts whose
    contents the sweep actually reports.
    """
    for label, extra in (("skip", ("--no-pdf",)), ("default", ())):
        out = tmp_path / label
        _scan(probe_target, out, *extra)
        for name in ("clean_report.json", "Scan_Performance.json",
                     "Security_CycloneDX.json", "Security_SPDX.spdx.json"):
            assert (out / name).exists(), f"{label} run is missing {name}"
