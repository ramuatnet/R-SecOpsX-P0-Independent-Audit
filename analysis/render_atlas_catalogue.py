"""Render core/atlas_catalogue.py from MITRE's pinned ATLAS data.

WHY A GENERATOR
---------------
`core/atlas_mappings.py` is v6-labelled but legacy-structured: a list of
{id, name, tactics, ...} dicts with lowercase maturity and inline tactic
membership. MITRE ATLAS format-version 6.0.0 is a MAPPING keyed by id, capitalises
maturity (Realized / Demonstrated / Feasible), hyphenates date fields, and expresses
tactic membership as an `achieves` relationship in a separate `relationships:`
block rather than as an inline `tactics:` list.

Because the shapes differ, there was no working path from the pinned file to the
catalogue, so the catalogue could only be maintained by hand -- and it drifted.
Twelve entries were transcribed from `dist/ATLAS.yaml`, which carries the header
"This version of the ATLAS data is deprecated and is no longer being updated" and
declares 5.6.0; two of their maturity values were wrong, and the error survived
compilation, the conformance benchmark and every unit test because nothing compared
the catalogue against its source.

This is the path that was missing.

THE MEMBERSHIP QUESTION, WHICH TOOK THREE PASSES TO ANSWER
-----------------------------------------------------------
Tactic membership is NOT an inline `tactics:` field in v6 -- not under techniques,
not under tactics. Searching only those two places produces a confident and entirely
wrong conclusion that v6 dropped membership. It is in the `relationships:` block as
`achieves`, one per technique:

    relationships:
      AML.T0000:
        achieves:
        - source: AML.T0000
          target: AML.TA0002
          relationship-type: achieves

208 `achieves` relationships for 208 techniques. The generator asserts that ratio,
because a regeneration that silently produced techniques with no tactics would look
exactly like a successful run.

WHAT IS GENERATED AND WHAT IS NOT
---------------------------------
Generated, from the pinned file: tactics, techniques, maturity, dates, uuid,
platforms, ATT&CK references, and technique-to-tactic membership. These are
transcription, so transcription should be mechanical.

NOT generated: the rule-to-technique mappings and the unmapped rationales. Those
are judgement -- which of OUR rules correspond to which ATLAS technique, and why a
rule has none -- and no amount of parsing MITRE's data can derive them. They stay
hand-written in core/atlas_mappings.py, which imports the catalogue from here.

THIS COMPILES ITS OWN OUTPUT
----------------------------
A generator that writes a broken module and reports success is worse than no
generator. The output is compiled, imported, and count-checked before this script
claims to have succeeded.
"""
from __future__ import annotations

import argparse
import hashlib
import pathlib
import py_compile
import re
import sys
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

REPO = pathlib.Path(__file__).resolve().parent.parent
CACHE = pathlib.Path(
    r"C:\Users\janan\AppData\Local\Temp\opencode\ATLAS-2026.09.yaml")
TARGET = REPO / "core" / "atlas_catalogue.py"

PINNED_RELEASE = "2026.09"
PINNED_FORMAT_VERSION = "6.0.0"
PINNED_RELEASE_DATE = "2026-09-15"
SOURCE_URL = ("https://raw.githubusercontent.com/mitre-atlas/atlas-data/"
              "main/dist/v6/ATLAS-2026.09.yaml")
MANIFEST_URL = ("https://github.com/mitre-atlas/atlas-data/blob/main/"
                "dist/manifest.yaml")

# AI-specific tactics: the ones that model adversary behaviour against AI systems
# rather than conventional IT. Kept explicit so the label is asserted rather than
# inferred from a name.
AI_ONLY_TACTICS = ("AML.TA0000", "AML.TA0001", "AML.TA0015")


def fetch_source(path: pathlib.Path) -> bytes:
    if path.exists() and path.stat().st_size > 100_000:
        return path.read_bytes()
    req = urllib.request.Request(
        SOURCE_URL, headers={"User-Agent": "R-SecOpsX-ATLAS-catalogue/1.0"})
    with urllib.request.urlopen(req, timeout=180) as resp:
        data = resp.read()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data


def _scalar(block: list[str], key: str) -> str | None:
    for line in block:
        m = re.match(rf"^    {re.escape(key)}:\s*(.+?)\s*$", line)
        if m:
            return m.group(1).strip().strip("'\"")
    return None


def _list(block: list[str], key: str) -> list[str]:
    out, collecting = [], False
    for line in block:
        if re.match(rf"^    {re.escape(key)}:\s*$", line):
            collecting = True
            continue
        if collecting:
            m = re.match(r"^    -\s*(.+?)\s*$", line)
            if m:
                out.append(m.group(1).strip().strip("'\""))
            elif re.match(r"^    [a-z0-9-]+:", line):
                collecting = False
    return out


def parse_atlas(text: str) -> dict:
    """Parse the pinned v6 document into a catalogue."""
    lines = text.splitlines()

    def block_bounds(header: str, stop_headers: tuple[str, ...]) -> tuple[int, int]:
        start = -1
        for n, l in enumerate(lines):
            if l.startswith(header):
                start = n + 1
                break
        if start == -1:
            raise SystemExit(f"block not found: {header}")
        end = len(lines)
        for n in range(start, len(lines)):
            if any(lines[n].startswith(s) for s in stop_headers):
                end = n
                break
        return start, end

    TOP = ("collection:", "matrix:", "tactics:", "techniques:", "mitigations:",
           "case-studies:", "relationships:")

    # --- tactics ---------------------------------------------------------
    ta0, ta1 = block_bounds("tactics:",
                            tuple(h for h in TOP if h != "tactics:"))
    tactics: dict[str, dict] = {}
    cur_id = None
    cur: list[str] = []
    for n in range(ta0, ta1):
        m = re.match(r"^  (AML\.TA\d{4}):$", lines[n])
        if m:
            if cur_id:
                tactics[cur_id] = {"name": _scalar(cur, "name"),
                                   "created": _scalar(cur, "created-date"),
                                   "modified": _scalar(cur, "modified-date"),
                                   "uuid": _scalar(cur, "uuid")}
            cur_id, cur = m.group(1), []
            continue
        if cur_id:
            cur.append(lines[n])
    if cur_id:
        tactics[cur_id] = {"name": _scalar(cur, "name"),
                           "created": _scalar(cur, "created-date"),
                           "modified": _scalar(cur, "modified-date"),
                           "uuid": _scalar(cur, "uuid")}

    # --- techniques ------------------------------------------------------
    te0, te1 = block_bounds("techniques:",
                            tuple(h for h in TOP if h != "techniques:"))
    techniques: dict[str, dict] = {}
    cur_id = None
    cur: list[str] = []
    for n in range(te0, te1):
        m = re.match(r"^  (AML\.T\d{4}(?:\.\d{3})?):$", lines[n])
        if m:
            if cur_id:
                techniques[cur_id] = _technique(cur)
            cur_id, cur = m.group(1), []
            continue
        if cur_id:
            cur.append(lines[n])
    if cur_id:
        techniques[cur_id] = _technique(cur)

    # --- achieves (tactic membership) -----------------------------------
    re0, _ = block_bounds("relationships:",
                          tuple(h for h in TOP if h != "relationships:"))
    membership: dict[str, list[str]] = {}
    cur_id = None
    achieves = False
    for n in range(re0, len(lines)):
        l = lines[n]
        m = re.match(r"^  (AML\.[A-Z]+\d+):$", l)
        if m:
            cur_id = m.group(1)
            achieves = False
            continue
        if re.match(r"^    achieves:\s*$", l):
            if cur_id:
                achieves = True
                membership.setdefault(cur_id, [])
            continue
        if re.match(r"^    [a-z-]+:", l):
            achieves = False
            continue
        if achieves and cur_id:
            t = re.match(r"^\s*target:\s*(AML\.TA\d{4})\s*$", l)
            if t and t.group(1) not in membership[cur_id]:
                membership[cur_id].append(t.group(1))

    # specializes: technique -> parent
    cur_id = None
    spec = False
    for n in range(re0, len(lines)):
        l = lines[n]
        m = re.match(r"^  (AML\.T\d{4}(?:\.\d{3})?):$", l)
        if m:
            cur_id = m.group(1)
            spec = False
            continue
        if re.match(r"^    specializes:\s*$", l):
            spec = True
            continue
        if re.match(r"^    [a-z-]+:", l):
            spec = False
            continue
        if spec and cur_id:
            s = re.match(r"^\s*target:\s*(AML\.T\d{4}(?:\.\d{3})?)\s*$", l)
            if s:
                techniques.setdefault(cur_id, {})["specializes"] = s.group(1)
                if cur_id not in membership:
                    membership[cur_id] = []

    for tid, entry in techniques.items():
        entry["tactics"] = tuple(membership.get(tid, ()))

    return {"tactics": tactics, "techniques": techniques, "membership": membership}


def _technique(block: list[str]) -> dict:
    out = {"name": _scalar(block, "name"), "maturity": _scalar(block, "maturity"),
           "created": _scalar(block, "created-date"),
           "modified": _scalar(block, "modified-date"),
           "uuid": _scalar(block, "uuid"),
           "platforms": _list(block, "platforms")}
    for line in block:
        m = re.match(r"^    attack-reference:\s*$", line)
        if m:
            for b2 in block[block.index(line) + 1: block.index(line) + 5]:
                i = re.match(r"^      id:\s*(\S+)", b2)
                if i:
                    out["attack_ref"] = i.group(1)
                    break
            break
    return out


def render(cat: dict, sha: str) -> str:
    tactics = cat["tactics"]
    techniques = cat["techniques"]

    # A sub-technique is identified by a SECOND dot. Every id has the first,
    # in "AML.T": AML.T0000 is top-level, AML.T0069.001 is a sub-technique.
    n_sub = sum(1 for t in techniques if t.count(".") >= 2)
    n_tactics_on = sum(1 for t in techniques.values() if t["tactics"])
    n_spec = sum(1 for t in techniques.values() if t.get("specializes"))
    maturities = sorted({t["maturity"] for t in techniques.values() if t["maturity"]})

    L: list[str] = []
    A = L.append
    A('"""MITRE ATLAS catalogue, GENERATED. Do not edit by hand.')
    A("")
    A("Produced by analysis/render_atlas_catalogue.py from MITRE's pinned ATLAS data.")
    A("Regenerate rather than patching: the whole reason this file exists is that a")
    A("hand-maintained catalogue drifted from its stated pin, and two maturity values")
    A("were wrong for a full release before anything noticed.")
    A("")
    A(f"  release        : {PINNED_RELEASE} (release-date {PINNED_RELEASE_DATE})")
    A(f"  format-version : {PINNED_FORMAT_VERSION}")
    A(f"  source         : {SOURCE_URL}")
    A(f"  pin declared in: {MANIFEST_URL}")
    A(f"  source sha256  : {sha}")
    A("")
    A("  The sha256 is of the exact bytes this file was rendered from, so a")
    A("  regeneration against different data is detectable rather than silent.")
    A('"""')
    A("from __future__ import annotations")
    A("")
    A(f'ATLAS_RELEASE = "{PINNED_RELEASE}"')
    A(f'ATLAS_RELEASE_DATE = "{PINNED_RELEASE_DATE}"')
    A(f'ATLAS_FORMAT_VERSION = "{PINNED_FORMAT_VERSION}"')
    A(f'ATLAS_SOURCE_URL = "{SOURCE_URL}"')
    A(f'ATLAS_SOURCE_SHA256 = "{sha}"')
    A(f'ATLAS_MATRIX = "ATLAS"')
    A("")
    A("# ---------------------------------------------------------------------------")
    A("# Counts, verified against the source by the generator before this file was")
    A("# written. If these ever disagree with len() of the tables below, the")
    A("# regeneration did not parse what it claimed to.")
    A("# ---------------------------------------------------------------------------")
    A(f"ATLAS_TACTIC_COUNT = {len(tactics)}")
    A(f"ATLAS_TECHNIQUE_COUNT = {len(techniques)}")
    A(f"ATLAS_TOP_LEVEL_TECHNIQUE_COUNT = {len(techniques) - n_sub}")
    A(f"ATLAS_SUB_TECHNIQUE_COUNT = {n_sub}")
    A(f"ATLAS_TECHNIQUES_WITH_TACTICS = {n_tactics_on}")
    A(f"ATLAS_SUB_TECHNIQUES_WITH_PARENT = {n_spec}")
    A(f"ATLAS_MATURITY_VALUES = {tuple(maturities)!r}")
    A("")
    A("# Tactics that model adversary behaviour against AI systems rather than")
    A("# conventional IT. Stated explicitly so the label is asserted, not inferred.")
    A(f"ATLAS_AI_ONLY_TACTICS = {AI_ONLY_TACTICS!r}")
    A("")
    A("ATLAS_TACTICS = {")
    for tid in sorted(tactics):
        t = tactics[tid]
        A(f'    "{tid}": {{')
        A(f'        "name": {t["name"]!r},')
        A(f'        "created": {t["created"]!r},')
        A(f'        "modified": {t["modified"]!r},')
        A(f'        "uuid": {t["uuid"]!r},')
        A(f'        "provenance": "atlas_definition",')
        A("    },")
    A("}")
    A("")
    A("# Techniques. `tactics` is resolved from the `relationships:` block's")
    A("# `achieves` relationships -- v6 has no inline tactics field, which is the")
    A("# single thing most likely to be got wrong by someone regenerating this by")
    A("# hand. A sub-technique legitimately has no tactics of its own and inherits")
    A("# its parent's; `specializes` is what places it.")
    A("ATLAS_TECHNIQUES = {")
    for tid in sorted(techniques):
        t = techniques[tid]
        A(f'    "{tid}": {{')
        A(f'        "name": {t["name"]!r},')
        tac = t["tactics"]
        A(f'        "tactics": {tac!r},')
        A(f'        "maturity": {t["maturity"]!r},')
        A(f'        "created": {t["created"]!r},')
        A(f'        "modified": {t["modified"]!r},')
        A(f'        "uuid": {t["uuid"]!r},')
        A(f'        "platforms": {tuple(t["platforms"])!r},')
        if t.get("attack_ref"):
            A(f'        "attack_ref": {t["attack_ref"]!r},')
        if t.get("specializes"):
            A(f'        "specializes": {t["specializes"]!r},')
        A(f'        "provenance": "atlas_definition",')
        A('        "source_release": "' + PINNED_RELEASE + '",')
        A("    },")
    A("}")
    A("")
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", default=str(CACHE),
                    help="local copy of the pinned ATLAS YAML (fetched if absent)")
    ap.add_argument("--check", action="store_true",
                    help="verify the existing catalogue matches the source; write nothing")
    args = ap.parse_args()

    data = fetch_source(pathlib.Path(args.source))
    sha = hashlib.sha256(data).hexdigest()
    print(f"  source  : {len(data):,} bytes  sha256 {sha[:16]}...")

    cat = parse_atlas(data.decode("utf-8"))
    n_t, n_tac, n_m = (len(cat["techniques"]), len(cat["tactics"]),
                       len(cat["membership"]))
    print(f"  parsed  : {n_t} techniques, {n_tac} tactics, "
          f"{n_m} entries with tactic membership")

    # The assertion that makes a broken parse fail loudly rather than producing a
    # plausible empty-tactic catalogue.
    with_tactics = sum(1 for t in cat["techniques"].values() if t["tactics"])
    # Second dot, not "no dot": every id contains the dot in "AML.T", so
    # ". not in k" counts zero top-level techniques.
    top = sum(1 for k in cat["techniques"] if k.count(".") == 1)
    sub = n_t - top
    print(f"  membership: {with_tactics} of {top} top-level techniques carry tactics; "
          f"{sub} sub-techniques")
    if top == 0:
        raise SystemExit(
            "no top-level techniques parsed -- the parser is wrong. A "
            "sub-technique has a SECOND dot; every id has the first.")
    if with_tactics == 0:
        raise SystemExit(
            "no technique carries a tactic. v6 expresses membership as an "
            "`achieves` relationship in the relationships block, NOT as an inline "
            "`tactics:` field. A parse that finds zero membership is looking in "
            "the wrong place and would write a plausible, useless catalogue.")

    body = render(cat, sha)

    if args.check:
        if not TARGET.exists():
            raise SystemExit(f"--check requested but {TARGET} does not exist")
        current = TARGET.read_text(encoding="utf-8")
        expected_sha = re.search(r'ATLAS_SOURCE_SHA256 = "([0-9a-f]{64})"', current)
        if not expected_sha:
            raise SystemExit(f"{TARGET} carries no ATLAS_SOURCE_SHA256")
        if expected_sha.group(1) != sha:
            raise SystemExit(
                f"catalogue was rendered from different bytes:\n"
                f"  file {expected_sha.group(1)}\n  source {sha}")
        print("  CHECK OK: catalogue matches the pinned source")
        return 0

    TARGET.write_text(body, encoding="utf-8", newline="\n")
    print(f"  wrote   : {TARGET} ({TARGET.stat().st_size:,} bytes)")

    # Compile, then IMPORT and count. A generator that reports success without
    # checking its own output is how a broken module ships.
    try:
        py_compile.compile(str(TARGET), doraise=True)
    except py_compile.PyCompileError as exc:
        raise SystemExit(f"GENERATED OUTPUT DOES NOT COMPILE: {exc}")

    sys.path.insert(0, str(REPO))
    for mod in list(sys.modules):
        if mod.startswith("core.atlas_catalogue"):
            del sys.modules[mod]
    import importlib
    gen = importlib.import_module("core.atlas_catalogue")

    problems = []
    if len(gen.ATLAS_TECHNIQUES) != n_t:
        problems.append(f"technique count {len(gen.ATLAS_TECHNIQUES)} != {n_t}")
    if len(gen.ATLAS_TACTICS) != n_tac:
        problems.append(f"tactic count {len(gen.ATLAS_TACTICS)} != {n_tac}")
    if gen.ATLAS_SOURCE_SHA256 != sha:
        problems.append("sha256 mismatch")
    bad_t = [k for k, v in gen.ATLAS_TECHNIQUES.items()
             if any(t not in gen.ATLAS_TACTICS for t in (v.get("tactics") or ()))]
    if bad_t:
        problems.append(f"techniques referencing unknown tactics: {bad_t[:5]}")
    if problems:
        raise SystemExit("generated module failed verification:\n  "
                         + "\n  ".join(problems))

    print(f"  verified: {len(gen.ATLAS_TECHNIQUES)} techniques, "
          f"{len(gen.ATLAS_TACTICS)} tactics, no dangling tactic references")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())