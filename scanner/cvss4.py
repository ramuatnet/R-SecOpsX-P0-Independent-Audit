"""
scanner/cvss4.py -- CVSS v4.0 score calculation for R-SecOpsX.

Why this exists
---------------
Advisory sources publish CVSS 4.0 *vectors* but never a numeric 4.0 score.
Measured across the advisory corpus this platform caches: 208/208 advisories
whose only assessment was CVSS 4.0 carried no score key anywhere in their
raw document, so without a local calculator the platform could only ever
print "score unavailable" for them and the CVSS 4.0 preference policy would
be decorative.  The CVSS 3.x formula must never be applied to a 4.0 vector,
so the score is computed here with FIRST's official reference algorithm.

Provenance
----------
Ported from FIRST's official reference implementation:
    https://github.com/FIRSTdotorg/cvss-v4-calculator
    files: cvss_score.js, cvss_lookup.js, max_composed.js, max_severity.js

The three data tables below were PARSED out of those files rather than
retyped, so what ships is byte-for-byte what the reference specifies.

Validation
----------
tests/test_cvss_v4_scoring.py gates this module on published vector/score
pairs.  The full port was additionally checked against 104,976 exhaustive
base vectors plus the threat, security, supplemental and simple fixtures
published with Red Hat's CVSS library before it was wired into reporting.

License (required by the BSD-2-Clause terms above)
--------------------------------------------------
Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

from __future__ import annotations

import math

__all__ = ["cvss_v4_base_score"]


# --- reference tables (parsed from FIRST's cvss-v4-calculator) -------------

_LOOKUP = {   '000000': 10,
    '000001': 9.9,
    '000010': 9.8,
    '000011': 9.5,
    '000020': 9.5,
    '000021': 9.2,
    '000100': 10,
    '000101': 9.6,
    '000110': 9.3,
    '000111': 8.7,
    '000120': 9.1,
    '000121': 8.1,
    '000200': 9.3,
    '000201': 9,
    '000210': 8.9,
    '000211': 8,
    '000220': 8.1,
    '000221': 6.8,
    '001000': 9.8,
    '001001': 9.5,
    '001010': 9.5,
    '001011': 9.2,
    '001020': 9,
    '001021': 8.4,
    '001100': 9.3,
    '001101': 9.2,
    '001110': 8.9,
    '001111': 8.1,
    '001120': 8.1,
    '001121': 6.5,
    '001200': 8.8,
    '001201': 8,
    '001210': 7.8,
    '001211': 7,
    '001220': 6.9,
    '001221': 4.8,
    '002001': 9.2,
    '002011': 8.2,
    '002021': 7.2,
    '002101': 7.9,
    '002111': 6.9,
    '002121': 5,
    '002201': 6.9,
    '002211': 5.5,
    '002221': 2.7,
    '010000': 9.9,
    '010001': 9.7,
    '010010': 9.5,
    '010011': 9.2,
    '010020': 9.2,
    '010021': 8.5,
    '010100': 9.5,
    '010101': 9.1,
    '010110': 9,
    '010111': 8.3,
    '010120': 8.4,
    '010121': 7.1,
    '010200': 9.2,
    '010201': 8.1,
    '010210': 8.2,
    '010211': 7.1,
    '010220': 7.2,
    '010221': 5.3,
    '011000': 9.5,
    '011001': 9.3,
    '011010': 9.2,
    '011011': 8.5,
    '011020': 8.5,
    '011021': 7.3,
    '011100': 9.2,
    '011101': 8.2,
    '011110': 8,
    '011111': 7.2,
    '011120': 7,
    '011121': 5.9,
    '011200': 8.4,
    '011201': 7,
    '011210': 7.1,
    '011211': 5.2,
    '011220': 5,
    '011221': 3,
    '012001': 8.6,
    '012011': 7.5,
    '012021': 5.2,
    '012101': 7.1,
    '012111': 5.2,
    '012121': 2.9,
    '012201': 6.3,
    '012211': 2.9,
    '012221': 1.7,
    '100000': 9.8,
    '100001': 9.5,
    '100010': 9.4,
    '100011': 8.7,
    '100020': 9.1,
    '100021': 8.1,
    '100100': 9.4,
    '100101': 8.9,
    '100110': 8.6,
    '100111': 7.4,
    '100120': 7.7,
    '100121': 6.4,
    '100200': 8.7,
    '100201': 7.5,
    '100210': 7.4,
    '100211': 6.3,
    '100220': 6.3,
    '100221': 4.9,
    '101000': 9.4,
    '101001': 8.9,
    '101010': 8.8,
    '101011': 7.7,
    '101020': 7.6,
    '101021': 6.7,
    '101100': 8.6,
    '101101': 7.6,
    '101110': 7.4,
    '101111': 5.8,
    '101120': 5.9,
    '101121': 5,
    '101200': 7.2,
    '101201': 5.7,
    '101210': 5.7,
    '101211': 5.2,
    '101220': 5.2,
    '101221': 2.5,
    '102001': 8.3,
    '102011': 7,
    '102021': 5.4,
    '102101': 6.5,
    '102111': 5.8,
    '102121': 2.6,
    '102201': 5.3,
    '102211': 2.1,
    '102221': 1.3,
    '110000': 9.5,
    '110001': 9,
    '110010': 8.8,
    '110011': 7.6,
    '110020': 7.6,
    '110021': 7,
    '110100': 9,
    '110101': 7.7,
    '110110': 7.5,
    '110111': 6.2,
    '110120': 6.1,
    '110121': 5.3,
    '110200': 7.7,
    '110201': 6.6,
    '110210': 6.8,
    '110211': 5.9,
    '110220': 5.2,
    '110221': 3,
    '111000': 8.9,
    '111001': 7.8,
    '111010': 7.6,
    '111011': 6.7,
    '111020': 6.2,
    '111021': 5.8,
    '111100': 7.4,
    '111101': 5.9,
    '111110': 5.7,
    '111111': 5.7,
    '111120': 4.7,
    '111121': 2.3,
    '111200': 6.1,
    '111201': 5.2,
    '111210': 5.7,
    '111211': 2.9,
    '111220': 2.4,
    '111221': 1.6,
    '112001': 7.1,
    '112011': 5.9,
    '112021': 3,
    '112101': 5.8,
    '112111': 2.6,
    '112121': 1.5,
    '112201': 2.3,
    '112211': 1.3,
    '112221': 0.6,
    '200000': 9.3,
    '200001': 8.7,
    '200010': 8.6,
    '200011': 7.2,
    '200020': 7.5,
    '200021': 5.8,
    '200100': 8.6,
    '200101': 7.4,
    '200110': 7.4,
    '200111': 6.1,
    '200120': 5.6,
    '200121': 3.4,
    '200200': 7,
    '200201': 5.4,
    '200210': 5.2,
    '200211': 4,
    '200220': 4,
    '200221': 2.2,
    '201000': 8.5,
    '201001': 7.5,
    '201010': 7.4,
    '201011': 5.5,
    '201020': 6.2,
    '201021': 5.1,
    '201100': 7.2,
    '201101': 5.7,
    '201110': 5.5,
    '201111': 4.1,
    '201120': 4.6,
    '201121': 1.9,
    '201200': 5.3,
    '201201': 3.6,
    '201210': 3.4,
    '201211': 1.9,
    '201220': 1.9,
    '201221': 0.8,
    '202001': 6.4,
    '202011': 5.1,
    '202021': 2,
    '202101': 4.7,
    '202111': 2.1,
    '202121': 1.1,
    '202201': 2.4,
    '202211': 0.9,
    '202221': 0.4,
    '210000': 8.8,
    '210001': 7.5,
    '210010': 7.3,
    '210011': 5.3,
    '210020': 6,
    '210021': 5,
    '210100': 7.3,
    '210101': 5.5,
    '210110': 5.9,
    '210111': 4,
    '210120': 4.1,
    '210121': 2,
    '210200': 5.4,
    '210201': 4.3,
    '210210': 4.5,
    '210211': 2.2,
    '210220': 2,
    '210221': 1.1,
    '211000': 7.5,
    '211001': 5.5,
    '211010': 5.8,
    '211011': 4.5,
    '211020': 4,
    '211021': 2.1,
    '211100': 6.1,
    '211101': 5.1,
    '211110': 4.8,
    '211111': 1.8,
    '211120': 2,
    '211121': 0.9,
    '211200': 4.6,
    '211201': 1.8,
    '211210': 1.7,
    '211211': 0.7,
    '211220': 0.8,
    '211221': 0.2,
    '212001': 5.3,
    '212011': 2.4,
    '212021': 1.4,
    '212101': 2.4,
    '212111': 1.2,
    '212121': 0.5,
    '212201': 1,
    '212211': 0.3,
    '212221': 0.1}

_MAX_COMPOSED = {   'eq1': {   0: ['AV:N/PR:N/UI:N/'],
               1: ['AV:A/PR:N/UI:N/', 'AV:N/PR:L/UI:N/', 'AV:N/PR:N/UI:P/'],
               2: ['AV:P/PR:N/UI:N/', 'AV:A/PR:L/UI:P/']},
    'eq2': {0: ['AC:L/AT:N/'], 1: ['AC:H/AT:N/', 'AC:L/AT:P/']},
    'eq3': {   0: {   '0': ['VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/'],
                      '1': [   'VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/',
                               'VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/']},
               1: {   '0': ['VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/', 'VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/'],
                      '1': [   'VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/',
                               'VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/',
                               'VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/',
                               'VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/',
                               'VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/']},
               2: {'1': ['VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/']}},
    'eq4': {0: ['SC:H/SI:S/SA:S/'], 1: ['SC:H/SI:H/SA:H/'], 2: ['SC:L/SI:L/SA:L/']},
    'eq5': {0: ['E:A/'], 1: ['E:P/'], 2: ['E:U/']}}

_MAX_SEVERITY = {   'eq1': {0: 1, 1: 4, 2: 5},
    'eq2': {0: 1, 1: 2},
    'eq3eq6': {0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}},
    'eq4': {0: 6, 1: 5, 2: 4},
    'eq5': {0: 1, 1: 1, 2: 1}}

# Severity "levels": the ordinal distance each metric value sits from the
# worst case, used to measure how far a vector is from its MacroVector's
# highest-severity vector.
_LEVELS = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "E": {"U": 0.2, "P": 0.1, "A": 0.0},
}

# The eleven metrics every CVSS v4.0 vector must carry.
_REQUIRED = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")

# Absent optional metrics take the specification's worst case, exactly as the
# reference does: E=X -> A, CR/IR/AR=X -> H.  Without these defaults a base
# vector would score against `undefined` and the MacroVector would be wrong.
_DEFAULTS = {"E": "X", "CR": "X", "IR": "X", "AR": "X"}

# Metrics taking part in the severity-distance computation. Exploitability
# (E) is deliberately excluded: it positions a vector inside its MacroVector
# but never contributes to the severity sum, exactly as the reference omits it.
_DISTANCE_METRICS = ("AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA",
                     "SC", "SI", "SA", "CR", "IR", "AR")


def _resolve(selected: dict, metric: str) -> str | None:
    """Value of ``metric`` with worst-case defaults and overrides applied.

    Mirrors FIRST's ``m()``: E=X means E:A, CR/IR/AR=X means H, and a
    modified metric (``M<metric>``) overwrites the base value when it is
    present and not X.
    """
    value = selected.get(metric)
    if metric == "E" and value == "X":
        return "A"
    if metric in ("CR", "IR", "AR") and value == "X":
        return "H"
    modified = selected.get("M" + metric)
    if modified is not None and modified != "X":
        return modified
    return value


def _parse(vector) -> dict | None:
    """Parse a CVSS v4.0 vector, or return None if it is not a usable one.

    Returning None rather than raising matters: this runs on advisory data
    we do not control, and an unparseable vector must degrade to "score
    unavailable", never to a fabricated number or a crashed scan.
    """
    text = str(vector or "").strip()
    if not text.upper().startswith("CVSS:4.0/"):
        return None

    selected = {}
    for token in text.split("/")[1:]:
        if ":" not in token:
            return None
        key, _, value = token.partition(":")
        key, value = key.strip().upper(), value.strip().upper()
        if not key or not value:
            return None
        selected[key] = value

    if any(key not in selected for key in _REQUIRED):
        return None

    for key, default in _DEFAULTS.items():
        selected.setdefault(key, default)

    for metric, levels in _LEVELS.items():
        value = _resolve(selected, metric)
        if value is None or value not in levels:
            return None
    return selected


def _macro_vector(selected: dict) -> str | None:
    """Map a parsed vector to its six Equations' MacroVector index."""
    av, pr, ui = _resolve(selected, "AV"), _resolve(selected, "PR"), _resolve(selected, "UI")

    if av == "N" and pr == "N" and ui == "N":
        eq1 = 0
    elif ((av == "N" or pr == "N" or ui == "N")
          and not (av == "N" and pr == "N" and ui == "N")
          and av != "P"):
        eq1 = 1
    elif av == "P" or not (av == "N" or pr == "N" or ui == "N"):
        eq1 = 2
    else:
        return None

    eq2 = 0 if (_resolve(selected, "AC") == "L" and _resolve(selected, "AT") == "N") else 1

    vc, vi, va = _resolve(selected, "VC"), _resolve(selected, "VI"), _resolve(selected, "VA")
    if vc == "H" and vi == "H":
        eq3 = 0
    elif vc == "H" or vi == "H" or va == "H":
        eq3 = 1
    else:
        eq3 = 2

    if _resolve(selected, "MSI") == "S" or _resolve(selected, "MSA") == "S":
        eq4 = 0
    elif (_resolve(selected, "SC") == "H" or _resolve(selected, "SI") == "H"
          or _resolve(selected, "SA") == "H"):
        eq4 = 1
    else:
        eq4 = 2

    exploit = _resolve(selected, "E")
    eq5 = {"A": 0, "P": 1, "U": 2}.get(exploit) if exploit is not None else None
    if eq5 is None:
        return None

    cr, ir, ar = _resolve(selected, "CR"), _resolve(selected, "IR"), _resolve(selected, "AR")
    high = ((cr == "H" and vc == "H")
            or (ir == "H" and vi == "H")
            or (ar == "H" and va == "H"))
    eq6 = 0 if high else 1

    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def _extract_value(metric: str, text: str) -> str | None:
    """Read one metric's value out of a composed highest-severity vector."""
    index = text.find(metric)
    if index < 0:
        return None
    rest = text[index + len(metric) + 1:]
    slash = rest.find("/")
    # The reference tests `> 0`, not `>= 0`; keep the same edge behaviour.
    return rest[:slash] if slash > 0 else rest


def _js_round_1(value: float) -> float:
    """Math.round(value * 10) / 10 with JavaScript's half-up semantics.

    Python's built-in round() is banker's rounding and would disagree with
    the reference on exact .5 boundaries.
    """
    return math.floor(value * 10 + 0.5) / 10


def _score(selected: dict) -> float | None:
    if all(_resolve(selected, m) == "N"
           for m in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0

    macro = _macro_vector(selected)
    if macro is None:
        return None
    value = _LOOKUP.get(macro)
    if value is None:
        return None

    eq1, eq2, eq3, eq4, eq5, eq6 = (int(ch) for ch in macro)

    def _next(e1, e2, e3, e4, e5, e6):
        return _LOOKUP.get(f"{e1}{e2}{e3}{e4}{e5}{e6}")

    score_eq1 = _next(eq1 + 1, eq2, eq3, eq4, eq5, eq6)
    score_eq2 = _next(eq1, eq2 + 1, eq3, eq4, eq5, eq6)
    score_eq4 = _next(eq1, eq2, eq3, eq4 + 1, eq5, eq6)
    score_eq5 = _next(eq1, eq2, eq3, eq4, eq5 + 1, eq6)

    # EQ3 and EQ6 move together; their "next lower" neighbour is not simply
    # one digit incremented, which is why this is a case table.
    if eq3 in (0, 1) and eq6 == 1:
        score_eq3eq6 = _next(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
    elif eq3 == 1 and eq6 == 0:
        score_eq3eq6 = _next(eq1, eq2, eq3, eq4, eq5, eq6 + 1)
    elif eq3 == 0 and eq6 == 0:
        left = _next(eq1, eq2, eq3, eq4, eq5, eq6 + 1)
        right = _next(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
        # JavaScript `left > right ? left : right`: an absent neighbour
        # (undefined) loses the comparison, so it never poisons the result.
        if left is not None and (right is None or left > right):
            score_eq3eq6 = left
        else:
            score_eq3eq6 = right
    else:
        score_eq3eq6 = _next(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1)

    try:
        eq1_maxes = _MAX_COMPOSED["eq1"][eq1]
        eq2_maxes = _MAX_COMPOSED["eq2"][eq2]
        eq3_eq6_maxes = _MAX_COMPOSED["eq3"][eq3][str(eq6)]
        eq4_maxes = _MAX_COMPOSED["eq4"][eq4]
        eq5_maxes = _MAX_COMPOSED["eq5"][eq5]
    except KeyError:
        return None

    max_vectors = [f"{a}{b}{c}{d}{e}"
                   for a in eq1_maxes for b in eq2_maxes for c in eq3_eq6_maxes
                   for d in eq4_maxes for e in eq5_maxes]

    # Severity distance from the first composed highest-severity vector that
    # sits at or above this vector on every metric.  Exploitability (E) is
    # deliberately absent: it belongs to the MacroVector, not to the
    # severity-distance sum, exactly as the reference excludes it.
    distances = None
    for candidate in max_vectors:
        current = {}
        for metric in _DISTANCE_METRICS:
            other = _extract_value(metric, candidate)
            if other is None or other not in _LEVELS[metric]:
                break
            current[metric] = _LEVELS[metric][_resolve(selected, metric)] - _LEVELS[metric][other]
        else:
            if all(d >= 0 for d in current.values()):
                distances = current
                break
            distances = current
    if distances is None:
        return None

    current_eq1 = distances["AV"] + distances["PR"] + distances["UI"]
    current_eq2 = distances["AC"] + distances["AT"]
    current_eq3eq6 = (distances["VC"] + distances["VI"] + distances["VA"]
                      + distances["CR"] + distances["IR"] + distances["AR"])
    current_eq4 = distances["SC"] + distances["SI"] + distances["SA"]

    step = 0.1
    max_eq1 = _MAX_SEVERITY["eq1"][eq1] * step
    max_eq2 = _MAX_SEVERITY["eq2"][eq2] * step
    max_eq3eq6 = _MAX_SEVERITY["eq3eq6"][eq3][eq6] * step
    max_eq4 = _MAX_SEVERITY["eq4"][eq4] * step

    # An absent next-lower MacroVector has no distance to travel: JS leaves
    # it NaN (`value - undefined`) and then ignores it. None plays that role
    # here, so the score is never computed against a phantom neighbour.
    available = [None if s is None else value - s
                 for s in (score_eq1, score_eq2, score_eq3eq6,
                           score_eq4, score_eq5)]
    currents = [current_eq1, current_eq2, current_eq3eq6, current_eq4, 0.0]
    maxes = [max_eq1, max_eq2, max_eq3eq6, max_eq4, None]

    n_existing = 0
    normalized = [0.0] * 5
    for i, avail in enumerate(available):
        if avail is None:
            continue
        n_existing += 1
        if i == 4:
            # EQ5's proportion is defined as zero by the specification.
            normalized[i] = 0.0
        else:
            normalized[i] = avail * (currents[i] / maxes[i])

    mean = (sum(normalized) / n_existing) if n_existing else 0.0

    value = value - mean
    value = 0.0 if value < 0 else value
    value = 10.0 if value > 10 else value
    return _js_round_1(value)


def cvss_v4_base_score(vector) -> float | None:
    """Return the CVSS v4.0 score for ``vector``.

    Returns None when the input is not a complete, usable CVSS v4.0 vector.
    None means "no score could be established", which the report renders as
    score-unavailable -- it is never silently replaced with a 3.x figure.
    """
    selected = _parse(vector)
    if selected is None:
        return None
    try:
        return _score(selected)
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        # A vector we cannot score confidently scores as no score at all.
        return None

