"""T-3.3 variant hunter: semantic stability of detection, per rule.

Given a labelled corpus TP (source->sink at a known line), generate
semantic variants -- rename the identifier, extract the sink argument to
a variable, concat->f-string, wrap in a helper, move the sink across a
module, add try/catch, alias the import, minify, reorder statements,
encode the payload, add a sanitizer -- re-scan every variant, and report

    detection_stability(rule) = detected / applicable

and a mutation-kill matrix per rule. Brittle regex rules become visible
as rows where stability < 1; a rule at 1.0 saw every variant.

Reverse mode injects a known-bad payload from the T-3.4 payload pack
into a SAFE fixture and measures the opposite direction: injected but
NOT reported = a false negative the pack just found.

Ground-rule discipline (same as analysis/validation/run.py): this
measures, it never edits the corpus or a label. A variant that loses
the vulnerability is the harness's fault and is reported as
transform_error, never as a detection miss. Family matching follows
analysis/validation/mutation.py: a hit whose rule_id or CWE matches the
anchor finding's family kills the variant, so a rename of the rule id
between layers does not fake a miss.

Usage:
    python -m analysis.validation.variant_hunter
    python -m analysis.validation.variant_hunter --json-out out.json
    python -m analysis.validation.variant_hunter --check-baseline
    python -m analysis.validation.variant_hunter --update-baseline
    python -m analysis.validation.variant_hunter --reverse
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
import sys
import tempfile
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

_LOG = logging.getLogger("rsx.analysis.validation.variant_hunter")

REPO = Path(__file__).resolve().parents[2]
BASELINE_PATH = REPO / "tests" / "validation" / "variant_stability_baseline.json"
REPORT_SCHEMA = "rsecopsx.variant_stability/v1"

from analysis.validation.corpus import (  # noqa: E402
    CORPUS_ROOT, family_of, iter_labelled,
)

# v1 transforms operate on Python fixtures (textual, conservative
# anchors). Other languages are counted and disclosed, never silently
# dropped.
_SUPPORTED_SUFFIX = ".py"

_PY_KEYWORDS = frozenset(
    "def class return import from if elif else while for in not and or "
    "try except finally with as None True False lambda yield pass raise "
    "global del assert async await print len open range str int list "
    "dict set tuple".split()
)


# --------------------------------------------------------------------------
# Transforms
# --------------------------------------------------------------------------
# A transform is fn(files: dict[str,str], anchor_file: str,
# anchor_line: int, evidence: str) -> dict[str,str] | None
# None means inapplicable to this anchor (counted, never faked).


def _t_rename_identifier(files, anchor_file, anchor_line, evidence):
    lines = files[anchor_file].splitlines()
    line = lines[anchor_line - 1]
    cands = [
        m.group(0) for m in re.finditer(r"[A-Za-z_]\w{2,}", line)
        if m.group(0) not in _PY_KEYWORDS and not m.group(0).isupper()
    ]
    if not cands:
        return None
    old = cands[0]
    new = f"ren_{old}"
    # Word-boundary replacement: a substring replace corrupts other
    # identifiers that contain the candidate (output -> ren_output also
    # rewrites check_output), which is a mangled file, not a rename.
    pattern = re.compile(rf"\b{re.escape(old)}\b")
    out = dict(files)
    out[anchor_file] = "\n".join(
        pattern.sub(new, ln) if not ln.lstrip().startswith("#")
        else ln for ln in lines) + "\n"
    return out


def _t_extract_to_var(files, anchor_file, anchor_line, evidence):
    lines = files[anchor_file].splitlines()
    line = lines[anchor_line - 1]
    ev = evidence.strip()
    if not ev or ev not in line:
        return None
    # Keep the anchor's indentation or the hoisted line lands at module
    # scope and the file stops parsing.
    indent = line[: len(line) - len(line.lstrip())]
    new_lines = list(lines)
    new_lines.insert(anchor_line - 1, f"{indent}_variant_tmp = {ev}")
    new_lines[anchor_line] = line.replace(ev, "_variant_tmp", 1)
    out = dict(files)
    out[anchor_file] = "\n".join(new_lines) + "\n"
    return out


def _t_concat_to_fstring(files, anchor_file, anchor_line, evidence):
    lines = files[anchor_file].splitlines()
    line = lines[anchor_line - 1]
    m = re.search(r"(['\"])(.+?)\1\s*\+\s*([A-Za-z_][\w.]*)", line)
    if not m:
        return None
    body, var = m.group(2), m.group(3)
    repl = f'f"{body}{{{var}}}"'
    out = dict(files)
    out[anchor_file] = "\n".join(
        line.replace(m.group(0), repl, 1) if i == anchor_line - 1 else ln
        for i, ln in enumerate(lines)) + "\n"
    return out


def _t_wrap_in_helper(files, anchor_file, anchor_line, evidence):
    lines = files[anchor_file].splitlines()
    line = lines[anchor_line - 1]
    if not line.strip() or line.lstrip().startswith("#"):
        return None
    helper_lines = ["def _variant_helper():", "    " + line.strip(), ""]
    new_lines = helper_lines + list(lines)
    # The anchor moved down by len(helper_lines) rows.
    new_lines[anchor_line - 1 + len(helper_lines)] = "_variant_helper()"
    out = dict(files)
    out[anchor_file] = "\n".join(new_lines) + "\n"
    return out


def _t_move_across_module(files, anchor_file, anchor_line, evidence):
    lines = files[anchor_file].splitlines()
    line = lines[anchor_line - 1]
    if not line.strip():
        return None
    helper_name = "_variant_moved_mod.py"
    if anchor_file == helper_name:
        return None
    helper_src = "def run_moved():\n    " + line.strip() + "\n"
    new_lines = list(lines)
    new_lines.insert(0, f"from {helper_name[:-3]} import run_moved")
    shifted = anchor_line - 1 + 1
    new_lines[shifted] = "run_moved()"
    out = dict(files)
    out[anchor_file] = "\n".join(new_lines) + "\n"
    out[helper_name] = helper_src
    return out


def _t_add_try_catch(files, anchor_file, anchor_line, evidence):
    lines = files[anchor_file].splitlines()
    line = lines[anchor_line - 1]
    if not line.strip():
        return None
    block = ["try:", "    " + line.strip(), "except Exception:", "    pass", ""]
    new_lines = list(lines[: anchor_line - 1]) + block + list(lines[anchor_line:])
    out = dict(files)
    out[anchor_file] = "\n".join(new_lines) + "\n"
    return out


def _t_alias_import(files, anchor_file, anchor_line, evidence):
    lines = files[anchor_file].splitlines()
    line = lines[anchor_line - 1]
    m = re.search(r"\b([A-Za-z_]\w*)\.\w+", line)
    if not m:
        return None
    mod = m.group(1)
    if not any(re.match(rf"import\s+{re.escape(mod)}\b", ln) for ln in lines):
        return None
    alias = f"{mod}_aliased"
    new_lines = [
        re.sub(rf"\bimport\s+{re.escape(mod)}\b(?!_)",
               f"import {mod} as {alias}", ln)
        if re.match(rf"\s*import\s+{re.escape(mod)}\b(?!_)", ln) else ln
        for ln in lines
    ]
    new_lines[anchor_line - 1] = re.sub(
        rf"\b{re.escape(mod)}\.", f"{alias}.", new_lines[anchor_line - 1])
    out = dict(files)
    out[anchor_file] = "\n".join(new_lines) + "\n"
    return out


def _t_minify(files, anchor_file, anchor_line, evidence):
    out = {}
    for name, text in files.items():
        kept = [
            ln.rstrip() for ln in text.splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")
        ]
        out[name] = "\n".join(kept) + "\n"
    return out


def _t_reorder_statements(files, anchor_file, anchor_line, evidence):
    lines = files[anchor_file].splitlines()
    anchor_i = anchor_line - 1
    anchor = lines[anchor_i]
    indent = anchor[: len(anchor) - len(anchor.lstrip())]
    anchor_ids = set(re.findall(r"[A-Za-z_]\w*", anchor))
    # Restrict the donor pool to the anchor's own block: pulling a line
    # out of (or into) another indentation block produces a syntax
    # error, which is a harness bug, not a semantic variant.
    start = anchor_i
    while start > 0 and lines[start - 1].strip() and (
            len(lines[start - 1]) - len(lines[start - 1].lstrip())
            == len(indent)):
        start -= 1
    end = anchor_i
    while end + 1 < len(lines) and lines[end + 1].strip() and (
            len(lines[end + 1]) - len(lines[end + 1].lstrip())
            == len(indent)):
        end += 1
    donor = None
    for i in range(start, end + 1):
        if i == anchor_i:
            continue
        s = lines[i].lstrip()
        if s.startswith(("import ", "from ", "#", "def ", "class ")):
            continue
        # Never move a statement that DEFINES a name the anchor reads
        # (the source assignment IS the vulnerability; relocating it can
        # delete the chain). Readers of shared names are fine to move.
        # Start-of-statement only: `shell=True` is a kwarg, not a def.
        m_assign = re.match(r"\s*([A-Za-z_]\w*)\s*=(?!=)", lines[i])
        if m_assign and m_assign.group(1) in anchor_ids:
            continue
        donor = i
        break
    if donor is None:
        return None
    moved = lines[donor]
    new_lines = [ln for i, ln in enumerate(lines) if i != donor]
    anchor_new = anchor_i - 1 if donor < anchor_i else anchor_i
    new_lines.insert(anchor_new + 1, moved)
    out = dict(files)
    out[anchor_file] = "\n".join(new_lines) + "\n"
    return out


def _t_change_encoding(files, anchor_file, anchor_line, evidence):
    from core.payload_pack import encode

    lines = files[anchor_file].splitlines()
    line = lines[anchor_line - 1]
    m = re.search(r"(['\"])([^'\"]{2,})\1", line)
    if not m:
        return None
    enc = encode(m.group(2), "url")
    out = dict(files)
    out[anchor_file] = "\n".join(
        line.replace(m.group(0), m.group(1) + enc + m.group(1), 1)
        if i == anchor_line - 1 else ln for i, ln in enumerate(lines)) + "\n"
    return out


# add_sanitizer is a PROBE, not a stability transform: sanitizing the
# source and still getting a hit flags a sanitizer-blind rule (an FP
# risk), so it is reported separately and never counted against
# detection_stability.
def _t_add_sanitizer(files, anchor_file, anchor_line, evidence):
    lines = files[anchor_file].splitlines()
    line = lines[anchor_line - 1]
    ev = evidence.strip()
    if not ev or ev not in line:
        return None
    out = dict(files)
    out[anchor_file] = "\n".join(
        line.replace(ev, f"str({ev})", 1) if i == anchor_line - 1 else ln
        for i, ln in enumerate(lines)) + "\n"
    return out


TRANSFORMS: dict[str, object] = {
    "rename_identifier": _t_rename_identifier,
    "extract_to_var": _t_extract_to_var,
    "concat_to_fstring": _t_concat_to_fstring,
    "wrap_in_helper": _t_wrap_in_helper,
    "move_across_module": _t_move_across_module,
    "add_try_catch": _t_add_try_catch,
    "alias_import": _t_alias_import,
    "minify": _t_minify,
    "reorder_statements": _t_reorder_statements,
    "change_encoding": _t_change_encoding,
}
SANITIZER_PROBE = "add_sanitizer"

# task.md lists these; v1 does not implement them and SAYS SO rather
# than shipping a stub that measures nothing.
TRANSFORMS_NOT_IMPLEMENTED = ("inline_var",)


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------
def _family_hit(findings: list[dict], rule_id: str, cwe: str) -> bool:
    cwe_l = (cwe or "").strip().lower()
    for f in findings:
        if rule_id and str(f.get("rule_id") or "") == rule_id:
            return True
        if cwe_l and str(f.get("cwe") or "").strip().lower() == cwe_l:
            return True
    return False


def _scan_dir(path: Path) -> list[dict]:
    from scanner.sast import scan_directory

    return scan_directory(str(path), workers=1)


def _run_case(files: dict[str, str], workroot: Path, tag: str) -> list[dict]:
    case_dir = workroot / tag
    case_dir.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (case_dir / name).write_text(text, encoding="utf-8")
    return _scan_dir(case_dir)


# --------------------------------------------------------------------------
# Reverse mode (FN measurement via the T-3.4 pack)
# --------------------------------------------------------------------------
PY_SINK_TEMPLATES: dict[str, str] = {
    "shell_injection": (
        "import subprocess\n"
        "subprocess.check_output('echo {payload}', shell=True)\n"
    ),
    "code_injection": "eval('{payload}')\n",
    "sql_injection": (
        "query = 'SELECT * FROM users WHERE name = ' + '{payload}'\n"
        "print(query)\n"
    ),
    "path_traversal": "open('{payload}').read()\n",
    "xss": "print('<div>' + '{payload}' + '</div>')\n",
    "ssrf": "import urllib.request\nurllib.request.urlopen('{payload}')\n",
    "insecure_deserialization": "import pickle\npickle.loads('{payload}'.encode())\n",
    "xxe": (
        "import xml.etree.ElementTree as ET\n"
        "ET.fromstring('{payload}')\n"
    ),
}


def reverse_scan(safe_fixtures: list[Path], limit_per_class: int = 1) -> dict:
    """Inject pack payloads into safe fixtures; report injected-but-missed."""
    from core.payload_pack import load_all

    results = []
    for class_id, cls in sorted(load_all().items()):
        cwe = cls["cwe"]
        template = PY_SINK_TEMPLATES.get(class_id)
        if template is None:
            results.append({"class": class_id, "status": "no_python_template"})
            continue
        payloads = cls["payloads"][:limit_per_class]
        for fixture in safe_fixtures:
            base = fixture.read_text(encoding="utf-8")
            for payload in payloads:
                injected = base + "\n" + template.format(payload=payload)
                files = {fixture.name: injected}
                findings = _run_case(
                    files, _reverse_root(), f"rev_{class_id}_{fixture.stem}")
                hit = _family_hit(findings, "", cwe)
                results.append({
                    "class": class_id,
                    "cwe": cwe,
                    "fixture": fixture.name,
                    "payload": payload,
                    "detected": hit,
                    "status": "fn" if not hit else "detected",
                })
    fn = [r for r in results if r.get("status") == "fn"]
    return {"cases": results, "new_fn_count": len(fn), "new_fns": fn}


_REVERSE_TMP: Path | None = None


def _reverse_root() -> Path:
    global _REVERSE_TMP
    if _REVERSE_TMP is None:
        _REVERSE_TMP = Path(tempfile.mkdtemp(prefix="rsx_rev_"))
    return _REVERSE_TMP


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------
def hunt(engine_label: str = "py") -> dict:
    per_rule: dict[str, dict] = {}
    per_transform: dict[str, dict] = {}
    baseline_misses: list[dict] = []
    skipped_lang = 0
    transform_errors: list[dict] = []
    workroot = Path(tempfile.mkdtemp(prefix="rsx_var_"))
    case_seq = [0]

    def _case_tag(label: str) -> str:
        case_seq[0] += 1
        return f"c{case_seq[0]:04d}_{label}"

    def _bucket(d, key):
        return d.setdefault(key, {"applicable": 0, "detected": 0, "missed": 0,
                                  "cases": []})

    try:
        for fixture, truth in iter_labelled(CORPUS_ROOT):
            fam = family_of(fixture, CORPUS_ROOT)
            if fam not in {"sast", "ai_ml"}:
                continue
            if fixture.suffix != _SUPPORTED_SUFFIX:
                skipped_lang += 1
                continue
            expected = (truth or {}).get("expected_findings") or []
            if not expected:
                continue  # safe fixture: reverse-mode material only
            source = fixture.read_text(encoding="utf-8")
            # Baseline on the SAME surface as the variants: a directory
            # scan of the fixture alone. scan_file skips the taint
            # engine, so a scan_file baseline mislabels taint-only
            # findings (SAST-SQLI, SAST-SSRF) as corpus misses.
            base_findings = _run_case(
                {fixture.name: source}, workroot, _case_tag("baseline"))
            rel = fixture.relative_to(CORPUS_ROOT).as_posix()
            for exp in expected:
                rule_id = str(exp.get("rule_id") or "")
                cwe = str(exp.get("cwe") or "")
                fam_hit = _family_hit(base_findings, rule_id, cwe)
                if not fam_hit:
                    baseline_misses.append({
                        "fixture": rel, "rule_id": rule_id, "cwe": cwe,
                        "line": exp.get("line"),
                    })
                    continue
                files = {fixture.name: source}
                for tname, fn in sorted(TRANSFORMS.items()):
                    try:
                        out = fn(files, fixture.name,
                                 int(exp.get("line") or 0),
                                 str(exp.get("evidence") or ""))
                    except Exception as exc:  # harness bug, disclosed
                        transform_errors.append({
                            "fixture": rel, "rule_id": rule_id,
                            "transform": tname, "error": str(exc),
                        })
                        continue
                    if out is None:
                        continue
                    findings = _run_case(out, workroot, _case_tag(tname))
                    hit = _family_hit(findings, rule_id, cwe)
                    for key, bucket_of in (
                        (rule_id or cwe, per_rule),
                        (tname, per_transform),
                    ):
                        b = _bucket(bucket_of, key)
                        b["applicable"] += 1
                        b["detected" if hit else "missed"] += 1
                        b["cases"].append({
                            "fixture": rel, "transform": tname,
                            "detected": hit,
                        })
                # Sanitizer probe (reported separately, never counted in
                # detection_stability).
                try:
                    probe_out = _t_add_sanitizer(
                        files, fixture.name, int(exp.get("line") or 0),
                        str(exp.get("evidence") or ""))
                except Exception:
                    probe_out = None
                if probe_out is not None:
                    findings = _run_case(probe_out, workroot,
                                         _case_tag("add_sanitizer"))
                    hit = _family_hit(findings, rule_id, cwe)
                    per_rule.setdefault(rule_id or cwe, {}).setdefault(
                        "sanitizer_probe", {"still_flagged": 0, "runs": 0})
                    sp = per_rule[rule_id or cwe]["sanitizer_probe"]
                    sp["runs"] += 1
                    sp["still_flagged"] += 1 if hit else 0
    finally:
        shutil.rmtree(workroot, ignore_errors=True)
        if _REVERSE_TMP is not None:
            shutil.rmtree(_REVERSE_TMP, ignore_errors=True)

    for d in (per_rule, per_transform):
        for b in d.values():
            if "applicable" in b:
                b["stability"] = (
                    round(b["detected"] / b["applicable"], 4)
                    if b["applicable"] else None)

    return {
        "schema": REPORT_SCHEMA,
        "engine": engine_label,
        "transforms": sorted(TRANSFORMS),
        "transforms_not_implemented": list(TRANSFORMS_NOT_IMPLEMENTED),
        "sanitizer_probe": SANITIZER_PROBE,
        "skipped_non_python_fixtures": skipped_lang,
        "baseline_misses": baseline_misses,
        "transform_errors": transform_errors,
        "per_rule": per_rule,
        "per_transform": per_transform,
    }


def check_baseline(report: dict, tolerance: float) -> list[str]:
    failures = []
    if not BASELINE_PATH.exists():
        return [f"baseline missing: {BASELINE_PATH} "
                "(run --update-baseline and commit it)"]
    base = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    base_rules = base.get("per_rule") or {}
    for rule_id, row in sorted((report.get("per_rule") or {}).items()):
        stab = row.get("stability")
        if stab is None:
            continue
        was = (base_rules.get(rule_id) or {}).get("stability")
        if was is None:
            failures.append(
                f"{rule_id}: not in baseline (stability {stab}) -- "
                "run --update-baseline and commit the new rows")
            continue
        if stab < was - tolerance:
            failures.append(
                f"{rule_id}: stability regressed {was} -> {stab} "
                f"(tolerance {tolerance})")
    for rule_id, row in sorted(base_rules.items()):
        if row.get("stability") is None:
            continue
        if (report.get("per_rule") or {}).get(rule_id) is None:
            failures.append(
                f"{rule_id}: in baseline (stability {row['stability']}) "
                "but absent from this run")
    return failures


def render_markdown(report: dict) -> str:
    """Human-readable stability report: per-rule table, per-transform
    kill matrix, reverse-mode FNs."""
    lines = ["# Variant stability report", ""]
    lines.append(f"- engine: {report['engine']}")
    lines.append(f"- transforms: {', '.join(report['transforms'])}")
    lines.append("- not implemented (disclosed): "
                 + ", ".join(report["transforms_not_implemented"]))
    lines.append(f"- non-python fixtures skipped: "
                 f"{report['skipped_non_python_fixtures']}")
    lines.append(f"- baseline misses: {len(report['baseline_misses'])}")
    lines.append(f"- transform errors: {len(report['transform_errors'])}")
    lines += ["", "## Per-rule detection stability", "",
              "| rule | stability | detected/applicable | sanitizer probe "
              "(still flagged/runs) |", "|---|---|---|---|"]
    for rule_id, row in sorted(report["per_rule"].items()):
        sp = row.get("sanitizer_probe") or {}
        probe = (f"{sp.get('still_flagged', 0)}/{sp.get('runs', 0)}"
                 if sp else "-")
        stab = row.get("stability")
        lines.append(
            f"| {rule_id} | {stab if stab is not None else '-'} "
            f"| {row.get('detected')}/{row.get('applicable')} | {probe} |")
    lines += ["", "## Mutation-kill matrix (rule x transform)", "",
              "| rule | " + " | ".join(report["transforms"]) + " |",
              "|---|" + "---|" * len(report["transforms"])]
    for rule_id, row in sorted(report["per_rule"].items()):
        cells = []
        for tname in report["transforms"]:
            hits = [c for c in row["cases"] if c["transform"] == tname]
            if not hits:
                cells.append("-")
            else:
                killed = sum(1 for c in hits if c["detected"])
                cells.append(f"{killed}/{len(hits)}")
        lines.append(f"| {rule_id} | " + " | ".join(cells) + " |")
    rev = report.get("reverse")
    if rev is not None:
        lines += ["", "## Reverse mode (injected, not reported = FN)", "",
                  f"- injected-but-missed: {rev['new_fn_count']}", ""]
        for fn in rev["new_fns"]:
            lines.append(
                f"- FN {fn['class']} ({fn['cwe']}) in {fn['fixture']}: "
                f"payload={fn['payload']!r}")
    if report["baseline_misses"]:
        lines += ["", "## Baseline misses (labelled TP, original not detected)",
                  ""]
        for m in report["baseline_misses"]:
            lines.append(f"- {m['fixture']}:{m['line']} {m['rule_id']} "
                         f"({m['cwe']})")
    if report["transform_errors"]:
        lines += ["", "## Transform errors (harness bugs, disclosed)", ""]
        for e in report["transform_errors"]:
            lines.append(f"- {e['fixture']} {e['transform']}: {e['error']}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="T-3.3 variant hunter")
    ap.add_argument("--json-out", help="write the full report here")
    ap.add_argument("--md-out", help="write the markdown report here")
    ap.add_argument("--check-baseline", action="store_true")
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--reverse", action="store_true",
                    help="inject pack payloads into safe fixtures (FN hunt)")
    ap.add_argument("--tolerance", type=float, default=0.05,
                    help="max per-rule stability drop vs baseline (5%%)")
    ap.add_argument("--reverse-limit", type=int, default=1,
                    help="payloads sampled per class in reverse mode")
    args = ap.parse_args(argv)

    report = hunt()
    if args.reverse:
        safe = [
            p for p, t in iter_labelled(CORPUS_ROOT)
            if family_of(p, CORPUS_ROOT) in {"sast", "ai_ml"}
            and p.suffix == _SUPPORTED_SUFFIX
            and (t or {}).get("expected_count") == 0
        ]
        report["reverse"] = reverse_scan(safe, args.reverse_limit)

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
    if args.md_out:
        Path(args.md_out).write_text(render_markdown(report),
                                     encoding="utf-8")

    rules = report["per_rule"]
    print(f"variant hunter: {len(rules)} rule(s) with applicable variants; "
          f"{len(report['baseline_misses'])} baseline miss(es); "
          f"{len(report['transform_errors'])} transform error(s); "
          f"non-python fixtures skipped: {report['skipped_non_python_fixtures']}")
    for rule_id, row in sorted(rules.items()):
        print(f"  {rule_id}: stability={row.get('stability')} "
              f"({row.get('detected')}/{row.get('applicable')})")
    if "reverse" in report:
        rev = report["reverse"]
        print(f"reverse mode: {rev['new_fn_count']} injected-but-missed case(s)")
        for fn in rev["new_fns"]:
            print(f"  FN {fn['class']} ({fn['cwe']}) in {fn['fixture']}: "
                  f"payload={fn['payload']!r}")

    if args.update_baseline:
        BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
        BASELINE_PATH.write_text(
            json.dumps(
                {"schema": REPORT_SCHEMA,
                 "per_rule": {k: {"stability": v.get("stability"),
                                  "applicable": v.get("applicable"),
                                  "detected": v.get("detected")}
                              for k, v in rules.items()}},
                indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        print(f"baseline written: {BASELINE_PATH}")
        return 0

    if args.check_baseline:
        failures = check_baseline(report, args.tolerance)
        if failures:
            print(f"\nVARIANT STABILITY: RED ({len(failures)} failure(s))")
            for f in failures:
                print(f"  - {f}")
            return 1
        print("\nVARIANT STABILITY: GREEN (no per-rule drop beyond "
              f"tolerance {args.tolerance})")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
