"""Regression guard for the LayoutError that silently cost a project its PDF.

`reporting/pdf_report.py::_code_safe_paragraph_chunks` bounded only the running
CHARACTER total across lines. A minified or bundled asset is ONE source line, so
it bypassed the cap entirely and became a single Paragraph of ~32,000 characters,
~4,300 points tall, against a 665-point frame. reportlab raised LayoutError,
`main.py` swallowed it into one console line, and BenchmarkJava-master shipped
with every artifact except both PDFs while still exiting 0.

Two guards are needed and they are different:

  * A functional test that no single rendered flowable exceeds the frame. This is
    what actually failed.
  * A structural test that the PDF failure is no longer INVISIBLE. The missing
    file was the worse half: a reader could not tell a report that had no PDF
    from one that had not been requested.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reporting import pdf_report as PR  # noqa: E402

# The Findings frame, taken from the LayoutError raised by the real build.
FRAME_W = 481.228346456693
FRAME_H = 665.48031496063


def render(source: str, cap: int = 1200) -> list:
    return PR._code_safe_paragraph_chunks(source, PR.S["Code"], cap)


def heights(source: str, cap: int = 1200) -> list:
    return [p.wrap(FRAME_W, FRAME_H)[1] for p in render(source, cap)]


# ===========================================================================
# The reported failure: one enormous minified line
# ===========================================================================

def test_minified_single_line_no_longer_bypasses_the_cap():
    """The exact shape that raised LayoutError: ~80,000 chars, no newlines."""
    src = "!function(a,b){" + "x" * 80000
    hs = heights(src)
    assert len(hs) > 1, "an 80,000-character line must not become one Paragraph"
    assert max(hs) <= FRAME_H, f"tallest paragraph {max(hs):.1f} exceeds the frame"


def test_no_rendered_code_paragraph_exceeds_the_frame():
    """The assertion that actually failed on BenchmarkJava."""
    for label, src in (
        ("minified", "!function(a,b){" + "x" * 80000),
        ("many one-char lines", "\n".join("x" for _ in range(200))),
        ("many two-char lines", "\n".join("ab" for _ in range(500))),
        ("mixed", ("a" * 3000 + "\n") * 20),
    ):
        hs = heights(src)
        assert hs, label
        assert max(hs) <= FRAME_H, f"{label}: {max(hs):.1f}pt exceeds {FRAME_H:.1f}pt"


def test_height_is_bounded_on_the_line_axis_too():
    """Character count alone does not bound height.

    1200 single-character lines is 1200 lines and about 13,200 points, so the
    line count needs its own bound. 200 lines is enough to prove the bound
    engages without being pathologically slow.
    """
    ps = render("\n".join("x" for _ in range(200)))
    assert len(ps) > 1, "line count must be bounded independently of length"
    assert max(p.wrap(FRAME_W, FRAME_H)[1] for p in ps) <= FRAME_H


# ===========================================================================
# NEGATIVE: normal input must be completely unaffected
# ===========================================================================

def test_ordinary_multi_line_snippet_is_still_one_paragraph():
    """NEGATIVE and load-bearing.

    An earlier version of the fix flattened every line into its own Paragraph,
    which bounded the height but changed layout for every report in the product.
    Ordinary snippets must group exactly as they did.
    """
    assert len(render("int a = 1;\nSystem.out.println(a);\n// tail")) == 1


def test_fifty_short_lines_stay_one_paragraph():
    assert len(render("\n".join(f"line {i};" for i in range(50)))) == 1


@pytest.mark.parametrize("src", [
    "",
    "a = 1;",
    "x" * 1200,                       # exactly at the cap
])
def test_short_and_boundary_inputs_are_unchanged(src):
    assert len(render(src)) == 1


def test_one_character_over_the_cap_splits():
    assert len(render("y" * 1201)) == 2


def test_line_boundaries_are_preserved_inside_a_chunk():
    """Source line boundaries must survive, or code evidence loses its shape."""
    out = render("a;\nb;\nc;")
    assert len(out) == 1
    text = out[0].getPlainText()
    assert "a;" in text and "b;" in text and "c;" in text


# ===========================================================================
# The splitter itself
# ===========================================================================

def test_short_line_is_returned_unchanged():
    assert PR._split_oversized_line("a b c", 1200) == ["a b c"]


def test_splitter_never_exceeds_the_cap():
    pieces = PR._split_oversized_line("z" * 5000, 1200)
    assert all(len(p) <= 1200 for p in pieces)
    assert "".join(pieces) == "z" * 5000, "splitting must be lossless"


def test_splitter_prefers_a_whitespace_boundary():
    line = "a" * 1100 + " " + "b" * 400
    pieces = PR._split_oversized_line(line, 1200)
    assert len(pieces) == 2
    assert pieces[1].strip().startswith("b")


def test_splitter_is_lossless_for_unbreakable_input():
    src = "q" * 7777
    assert "".join(PR._split_oversized_line(src, 300)) == src


@pytest.mark.parametrize("bad", [0, -1])
def test_non_positive_cap_does_not_loop_forever(bad):
    """NEGATIVE: a zero or negative cap must not become an infinite loop."""
    assert len(PR._split_oversized_line("abcdef", bad)) == 1


# ===========================================================================
# No invisible characters in evidence
# ===========================================================================

def test_no_zero_width_characters_are_injected_into_evidence():
    """NEGATIVE and load-bearing.

    A zero-width-space approach was tried and removed. It does not help height
    (a 1200-character token already wraps to 72 points) and it silently attaches
    invisible U+200B to every code paragraph, so a reader copying evidence out of
    the PDF would get those characters with it. Evidence fidelity outranks
    cosmetics.
    """
    src = 'a="x"; if (b) { c(d); } // <br/> &amp; &quot;'
    out = render(src)
    assert out
    for p in out:
        assert "\u200b" not in p.getPlainText()
        assert "\u200c" not in p.getPlainText()
        assert "\u200d" not in p.getPlainText()


def test_html_like_source_stays_code_not_markup():
    """Pre-existing guarantee that must survive the fix."""
    out = render("if (a < b && c > d) { x = \"<br/>\"; }")
    assert len(out) == 1
    text = out[0].getPlainText()
    assert "<br/>" in text, "the literal text <br/> must survive as characters"


# ===========================================================================
# Structural: a missing PDF must not be invisible again
# ===========================================================================

def test_main_does_not_swallow_exporter_failures_into_a_print():
    """NEGATIVE: the worse half of the defect.

    Both PDF generators were wrapped in `except Exception: _safe_print(...)`. A
    run that produced no PDF still exited 0 and the console line was easy to miss,
    so a report with no PDF looked identical to a report where none was
    requested. Failures must be accumulated and reported at the end.
    """
    src = (ROOT / "main.py").read_text(encoding="utf-8")
    assert "_REPORT_EXPORT_FAILURES" in src, (
        "exporter failures are not accumulated, so a lost PDF is silent again")
    assert re.search(r"except Exception as \w+:\s*\n\s*_REPORT_EXPORT_FAILURES\.append",
                     src), "an exporter except block does not record its failure"


def test_main_reports_export_failures_at_the_end_of_the_run():
    src = (ROOT / "main.py").read_text(encoding="utf-8")
    assert "REPORT EXPORT FAILURES" in src, (
        "accumulated failures are never surfaced to the operator")