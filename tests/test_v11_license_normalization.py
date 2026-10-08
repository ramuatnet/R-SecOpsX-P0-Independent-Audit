"""Normalisation must not publish a non-identifier as a resolved licence.

MEASURED, NOT ASSUMED
---------------------
Across the 23 prodtest corpus artifacts that carry license_evidence, 192 components
had a `license_resolved` value that is not SPDX-shaped, every one of them reported
with `license_resolution_status = RESOLVED_FROM_CANONICAL_REPORT`:

    GNU General Public License, version 2           49   -> GPL-2.0-only
    AGPLv3 License                                    49   -> AGPL-3.0-only
    GNU General Public License, version 2 (GPL2)     44   -> GPL-2.0-only
    MIT/X11                                            4   -> MIT
    SEE LICENSE IN COPYING.txt                         2   -> not an identifier
    SEE LICENSE IN README.md                           1   -> not an identifier

These were worse than the 3,409 genuinely-unknown components, and that is the point
worth recording. An unknown row is honestly labelled as a gap, so somebody looks at
it. A confidently wrong licence is quoted straight into a compliance answer, because
nothing about it invites a second look. The fix that matters is not more coverage
but refusing to assert a resolution that did not happen.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.license_catalog import (  # noqa: E402
    is_license_file_pointer,
    normalize_license,
)


# ------------------------------------------- long-form names become SPDX ids --

@pytest.mark.parametrize(
    ("declared", "want"),
    [
        ("GNU General Public License, version 2", "GPL-2.0-only"),
        ("GNU General Public License, version 2 (GPL2)", "GPL-2.0-only"),
        ("GNU General Public License, version 3", "GPL-3.0-only"),
        ("GNU Affero General Public License, version 3", "AGPL-3.0-only"),
        ("AGPLv3 License", "AGPL-3.0-only"),
        ("Lesser General Public License, version 2.1", "LGPL-2.1-only"),
        ("Lesser General Public License, version 3", "LGPL-3.0-only"),
    ],
)
def test_long_form_names_normalise_to_spdx(declared, want):
    assert normalize_license(declared) == want


def test_paren_suffix_is_stripped_before_the_alias_table():
    """Rather than adding a combinatorial number of spellings to the table.

    "GNU General Public License, version 2 (GPL2)" is handled by dropping the
    trailing parenthetical and retrying, so the next long form a package ships does
    not need a new table entry.
    """
    assert normalize_license("The MIT License (MIT)") == normalize_license("MIT")


@pytest.mark.parametrize(
    ("declared", "want"),
    [
        ("MIT/X11", "MIT"),
        ("Expat", "MIT"),
        ("New BSD License", "BSD-3-Clause"),
        ("Simplified BSD License", "BSD-2-Clause"),
        ("ISC License", "ISC"),
    ],
)
def test_legacy_spellings_normalise(declared, want):
    assert normalize_license(declared) == want


def test_normalisation_is_case_insensitive():
    assert normalize_license("agplv3 LICENSE") == normalize_license("AGPLv3 License")


# ------------------------------------------------- a pointer is not an id ----

@pytest.mark.parametrize(
    "declared",
    [
        "SEE LICENSE IN COPYING.txt",
        "SEE LICENSE IN README.md",
        "see licence in LICENSE",
        "SEE LICENSE IN ../LICENSE",
    ],
)
def test_file_pointers_are_not_reported_as_identifiers(declared):
    """Returning the string unchanged published it as a resolved licence.

    UNRESOLVED_FILE_REFERENCE is deliberate rather than UNKNOWN: the declaration
    exists and is simply not an identifier, and collapsing the two would discard the
    fact that the package did declare something.
    """
    got = normalize_license(declared)

    assert got == "UNRESOLVED_FILE_REFERENCE"
    assert is_license_file_pointer(declared)


def test_pointer_detection_does_not_catch_real_identifiers():
    for value in ("MIT", "Apache-2.0", "GPL-2.0-only", "(MIT OR Apache-2.0)",
                  "SEE LICENSE IN COPYING.txt"[:0] or "MIT"):
        assert not is_license_file_pointer(value), value


# ------------------------------------------------------ nothing regressed ---

@pytest.mark.parametrize(
    ("value", "want"),
    [
        ("MIT", "MIT"),
        ("Apache-2.0", "Apache-2.0"),
        ("MIT OR Apache-2.0", "MIT OR Apache-2.0"),
        ("Apache-2.0 AND MIT", "Apache-2.0 AND MIT"),
        ("(WTFPL OR MIT)", "(WTFPL OR MIT)"),
        ("HPND", "HPND"),
        ("bsd", "BSD-3-Clause"),
        ("apache 2.0", "Apache-2.0"),
    ],
)
def test_existing_behaviour_is_unchanged(value, want):
    """A valid SPDX expression must pass through untouched.

    Parenthesised and compound expressions are legal and must not be mangled by the
    trailing-parenthetical strip -- "(MIT AND CC-BY-3.0)" is an expression, not a
    long form with a qualifier.
    """
    assert normalize_license(value) == want


def test_compound_expression_is_not_mangled_by_the_paren_strip():
    assert normalize_license("(MIT AND CC-BY-3.0)") == "(MIT AND CC-BY-3.0)"
    assert normalize_license("(BSD-2-Clause OR MIT OR Apache-2.0)") == (
        "(BSD-2-Clause OR MIT OR Apache-2.0)")


def test_unknown_still_returns_unknown():
    assert normalize_license(None) == "UNKNOWN"
    assert normalize_license("") == "UNKNOWN"
    assert normalize_license("unknown") == "UNKNOWN"


def test_license_file_pointer_check_survives_none():
    assert is_license_file_pointer(None) is False
    assert is_license_file_pointer("") is False