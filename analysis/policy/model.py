"""Policy-as-code gate model (T-8.3, task.md section 11).

Rego is NOT adopted: an OPA/Rego runtime would be a required external
dependency, breaking the offline/airgap invariant for scan-time
components and the in-suite testability of the gate. The policy
language is a documented YAML subset (see policy_yaml.py); PyYAML is
used when importable, the subset parser otherwise, and both paths are
pinned equal for the canonical document.

Semantics locked by tests/test_t83_policy.py:

* fail_on is NORMALIZED TO ITS LOWEST RUNG with or-above blocking --
  the list form replaces main.py's hardcoded --fail-on rung logic and
  is never weaker than it (['high'] blocks Critical too; ['critical',
  'medium'] is rung medium);
* scope_include / scope_exclude are true ** globs over the row's file
  (SCA rows with file=None bypass file globs); non-matching rows are
  annotated out_of_scope, never silently dropped;
* exclusions match rule + optional file glob + optional line; a
  suppression without a reason can never load (loud at parse time);
* SLA per severity (sla_<sev>: days) breaches BLOCK independently of
  fail_on; an unparseable/missing age is annotated sla_age_unknown and
  counts, but does not block (fail-open on unknown age, disclosed --
  scan findings carry no first_seen, fail-closed would block all);
* required_evidence keys: a BLOCKING row missing one stays blocking
  and carries a machine note (fail-closed -- a gate must not pass on
  thin findings); non-blocking rows are annotated only;
* unrecognised severities and non-dict rows are counted and noted,
  never raised and never blocking.
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_M1
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import WINDOW_M1

import datetime as _dt
import re

from . import policy_yaml

POLICY_SCHEMA = "rsecopsx.policy/v1"
RESULT_SCHEMA = "rsecopsx.policy_result/v1"
DOC_SCHEMA = "rsecopsx.policy_doc/v1"
SEVERITIES = ("critical", "high", "medium", "low", "info")

_COUNT_KEYS = ("pass", "blocking", "excluded", "out_of_scope",
               "sla_age_unknown", "severity_unrecognised",
               "rows_not_objects")


class PolicyInvalid(Exception):
    """A policy document failed validation; .reason is machine-stable."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


# ---------------------------------------------------------------------------
# loading + normalization
# ---------------------------------------------------------------------------


def parse_policy(text):
    """Parse *text* (YAML subset) into the normalized policy dict."""
    try:
        import yaml
    except ImportError:
        try:
            raw = policy_yaml.loads(text)
        except policy_yaml.PolicyYamlError as exc:
            raise PolicyInvalid(f"policy_unreadable_yaml:{exc}") from exc
    else:
        try:
            raw = yaml.safe_load(text)
        except Exception as exc:  # noqa: BLE001 - any YAML error is loud
            raise PolicyInvalid(f"policy_unreadable_yaml:{exc}") from exc
    return _normalize(raw)


def load_policy_file(path):
    """Read and parse a policy file; a missing file is loud."""
    import pathlib
    p = pathlib.Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyInvalid(f"policy_file_missing:{p}") from exc
    return parse_policy(text)


def _normalize(raw):
    if not isinstance(raw, dict):
        raise PolicyInvalid("policy_not_object")
    if raw.get("schema") != POLICY_SCHEMA:
        raise PolicyInvalid("policy_schema")

    name = raw.get("name")
    if name is not None and not isinstance(name, str):
        raise PolicyInvalid("policy_name_invalid")

    fail_on = _sev_tuple(raw.get("fail_on"), "fail_on")
    for sev in fail_on:
        if sev not in SEVERITIES:
            raise PolicyInvalid(f"fail_on_unknown_severity:{sev}")
    # the rung is the LOWEST severity in the list: index grows as
    # severity falls, so the lowest rung has the highest index; the
    # gate then blocks every severity at-or-above that index
    rung = max(fail_on, key=SEVERITIES.index) if fail_on else None

    scope_include = _str_tuple(raw.get("scope_include"), "scope_invalid")
    scope_exclude = _str_tuple(raw.get("scope_exclude"), "scope_invalid")

    sla = {}
    nested = raw.get("sla")
    if nested is not None:
        if not isinstance(nested, dict):
            raise PolicyInvalid("sla_invalid")
        for sev, days in nested.items():
            _sla_put(sla, sev, days)
    for key, value in raw.items():
        if isinstance(key, str) and key.startswith("sla_"):
            _sla_put(sla, key[len("sla_"):], value)

    required_evidence = _str_tuple(raw.get("required_evidence"),
                                   "evidence_invalid")
    for key in required_evidence:
        if not key:
            raise PolicyInvalid("evidence_invalid")

    exclusions = _normalize_exclusions(raw.get("exclusions"))

    return {
        "schema": POLICY_SCHEMA,
        "name": name,
        "fail_on": fail_on,
        "rung": rung,
        "scope_include": scope_include,
        "scope_exclude": scope_exclude,
        "sla": sla,
        "required_evidence": required_evidence,
        "exclusions": exclusions,
    }


def _sev_tuple(value, invalid_reason):
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)) and all(
            isinstance(v, str) for v in value):
        return tuple(value)
    raise PolicyInvalid(invalid_reason)


def _str_tuple(value, invalid_reason):
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)) and all(
            isinstance(v, str) for v in value):
        return tuple(value)
    raise PolicyInvalid(invalid_reason)


def _sla_put(sla, sev, days):
    if sev not in SEVERITIES:
        raise PolicyInvalid(f"sla_unknown_severity:{sev}")
    if isinstance(days, bool) or not isinstance(days, int) or days <= 0:
        raise PolicyInvalid(f"sla_bad_days:{sev}")
    sla[sev] = days


def _normalize_exclusions(value):
    if value is None:
        return ()
    if not isinstance(value, list):
        raise PolicyInvalid("exclusions_invalid")
    out = []
    for i, item in enumerate(value):
        if not isinstance(item, dict):
            raise PolicyInvalid(f"exclusion_not_object:{i}")
        if not item.get("reason"):
            raise PolicyInvalid(f"exclusion_missing_reason:{i}")
        if not item.get("rule"):
            raise PolicyInvalid(f"exclusion_missing_rule:{i}")
        allowed = {"rule", "reason", "file", "line"}
        for key in item:
            if key not in allowed:
                raise PolicyInvalid(f"exclusion_unknown_key:{i}:{key}")
        entry = {"rule": item["rule"], "reason": item["reason"]}
        if "file" in item:
            if not isinstance(item["file"], str) or not item["file"]:
                raise PolicyInvalid(f"exclusion_bad_file:{i}")
            entry["file"] = item["file"]
        if "line" in item:
            line = item["line"]
            if isinstance(line, bool) or not isinstance(line, int):
                raise PolicyInvalid(f"exclusion_bad_line:{i}")
            entry["line"] = line
        out.append(entry)
    return tuple(out)


# ---------------------------------------------------------------------------
# glob matching (own compiler: fnmatch's * crosses '/', and '**/*.py'
# must also match top-level files)
# ---------------------------------------------------------------------------


def _glob_re(glob):
    out = []
    i, n = 0, len(glob)
    while i < n:
        c = glob[i]
        if c == "*":
            if glob.startswith("**/", i):
                out.append("(?:.*/)?")
                i += 3
            elif glob.startswith("**", i):
                out.append(".*")
                i += 2
            else:
                out.append("[^/]*")
                i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("".join(out) + r"\Z", re.IGNORECASE)


def _matches(path, regexes):
    return any(rx.match(path) for rx in regexes)


# ---------------------------------------------------------------------------
# evaluation
# ---------------------------------------------------------------------------


def evaluate(policy, rows, as_of):
    """Evaluate *rows* under *policy*; pure, deterministic, sorted."""
    inc = tuple(_glob_re(g) for g in policy["scope_include"])
    exc = tuple(_glob_re(g) for g in policy["scope_exclude"])
    # index exclusions by rule: the matcher stays O(rows) even with
    # hundreds of suppressions (perf test drives 10k rows x 200 rules)
    excl_by_rule = {}
    for e in policy["exclusions"]:
        excl_by_rule.setdefault(e["rule"], []).append(
            (_glob_re(e["file"]) if "file" in e else None,
             e.get("line"), e["reason"]))
    rung = policy["rung"]
    rung_idx = SEVERITIES.index(rung) if rung else None
    sla = policy["sla"]
    required = policy["required_evidence"]

    out_rows = []
    blocking = []
    counts = {k: 0 for k in _COUNT_KEYS}

    for row in rows:
        if not isinstance(row, dict):
            counts["rows_not_objects"] += 1
            continue
        rule_id = row.get("rule_id")
        file = row.get("file")
        line = row.get("line")
        sev_raw = row.get("severity")
        sev = str(sev_raw).strip().lower() if sev_raw is not None else ""
        notes = []
        reasons = []
        note = None

        if sev not in SEVERITIES:
            counts["severity_unrecognised"] += 1
            notes.append(f"severity_unrecognised:{sev}")

        # exclusions first: a reasoned human decision (rule + optional
        # file/line + mandatory reason) outranks the scope filters, so
        # the artifact keeps the reason instead of a scope label;
        # matched only post-scanner-suppression, independent of the
        # inline/.sastignore/baseline precedence chain
        status = None
        if file is not None:
            path = str(file).replace("\\", "/")
        else:
            path = None
        for file_rx, excl_line, reason in excl_by_rule.get(rule_id, ()):
            if file_rx is not None and (path is None
                                        or not file_rx.match(path)):
                continue
            if excl_line is not None and excl_line != line:
                continue
            status, note = "excluded", reason
            break

        # scope -- file-less rows (SCA packages) bypass file globs
        if status is None and file is not None:
            path = str(file).replace("\\", "/")
            if inc and not _matches(path, inc):
                status, note = "out_of_scope", "scope_not_included"
            elif exc and _matches(path, exc):
                status, note = "out_of_scope", "scope_excluded"

        # SLA breach blocks independently of fail_on
        if status is None and sev in sla:
            age = _age_days(row, as_of)
            if age is None:
                counts["sla_age_unknown"] += 1
                notes.append("sla_age_unknown")
            elif age > sla[sev]:
                reasons.append("sla_breach")

        # fail_on rung, or-above
        if status is None and rung_idx is not None and sev in SEVERITIES:
            if SEVERITIES.index(sev) <= rung_idx:
                reasons.append("fail_on_rung")

        if status is None:
            if reasons:
                status = "blocking"
                # required evidence: fail-closed on blocking rows
                for key in required:
                    if key not in row or row[key] in (None, ""):
                        notes.append(f"missing_evidence:{key}")
            else:
                status = "pass"
                for key in required:
                    if key not in row or row[key] in (None, ""):
                        notes.append(f"missing_evidence:{key}")

        out = {
            "rule_id": rule_id,
            "file": file,
            "line": line,
            "severity": sev,
            "status": status,
            "reasons": reasons,
            "note": note,
            "notes": notes,
        }
        out_rows.append(out)
        counts[status] = counts.get(status, 0) + 1
        if status == "blocking":
            blocking.append({
                "rule_id": rule_id, "file": file, "line": line,
                "severity": sev, "reasons": list(reasons),
            })

    out_rows.sort(key=_row_sort_key)
    blocking.sort(key=_row_sort_key)

    return {
        "schema": RESULT_SCHEMA,
        "policy": {
            "schema": policy["schema"],
            "name": policy["name"],
            "fail_on": list(policy["fail_on"]),
            "rung": policy["rung"],
            "sla": dict(policy["sla"]),
            "required_evidence": list(policy["required_evidence"]),
            "exclusions": len(policy["exclusions"]),
        },
        "as_of": as_of,
        "passed": counts["blocking"] == 0,
        "rows": out_rows,
        "blocking": blocking,
        "counts": counts,
        "skips": [],
    }


def _row_sort_key(row):
    line = row.get("line")
    return (str(row.get("rule_id") or ""),
            str(row.get("file") or ""),
            line if isinstance(line, int) and not isinstance(line, bool)
            else -1)


def _age_days(row, as_of):
    raw = row.get("first_seen")
    if raw is None:
        raw = row.get("created_at")
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        ts = float(raw)
    elif isinstance(raw, str):
        text = raw.strip()
        if text.endswith("Z"):
            text = text[:WINDOW_M1] + "+00:00"
        try:
            parsed = _dt.datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_dt.timezone.utc)
        ts = parsed.timestamp()
    else:
        return None
    return (as_of - ts) / 86400.0


# ---------------------------------------------------------------------------
# payload adapter (mirrors main.py's _is_vulnerable_package /
# _package_severity so policy rows and the hardcoded gate agree)
# ---------------------------------------------------------------------------


def rows_from_payload(payload):
    """Flatten a scan payload into policy rows (findings + SCA)."""
    rows = []
    findings = payload.get("findings") or []
    for finding in findings:
        rows.append(finding)
    packages = payload.get("sbom") or []
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        if not (pkg.get("vulnerabilities") or pkg.get("cve")
                or pkg.get("advisory_id")):
            continue
        sev = (pkg.get("severity")
               or pkg.get("highest_vulnerability_severity")
               or "Unknown")
        name = pkg.get("name") or pkg.get("package") or "unknown"
        rows.append({
            "rule_id": f"sca:{name}",
            "file": None,
            "line": None,
            "severity": sev,
            "message": "vulnerable dependency package",
        })
    return rows
