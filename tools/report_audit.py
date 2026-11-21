"""ftasks test-policy command 3: audit one scan's artifacts.

    python tools/report_audit.py /tmp/r [--baseline]

Reads the output directory produced by ``python -m scanner.cli`` and checks
every invariant registered in ``CHECKS``.  Any violation prints a
``VIOLATION <id>: <message>`` line, the run ends with a count summary, and
the exit code is 1 — command 3 exits non-zero on *any* invariant breach
(ftasks §1).

The check list grows one entry per ftasks phase (P0 registers the FND
invariants; later phases append theirs).  ``--baseline`` diffs the current
artifacts against the committed SHA manifest produced by ``tools/baseline.py``
(FND-08).

Deliberately stdlib-only at P0: existence/structure/arithmetic checks need
no parser beyond json.  Cross-artifact extraction (PDF/XLSX headline
counts) arrives with the renderer-parity phases.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Callable

# Bootstrap like the parity test: run as `python tools/report_audit.py`,
# sys.path[0] is tools/, not the repo root — core.* must still import.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

MIN_ARTIFACT_BYTES = 1024
#: Keys every payload-level filter_trace entry must carry (FND-01).
TRACE_ENTRY_KEYS = {"stage", "rule", "path", "line", "reason"}

Check = Callable[[Path, dict], list[str]]
# A check receives (out_dir, payload) and returns a list of violation
# messages (empty == pass).  Payload may be None when clean_report.json
# is missing/unparsable — checks must tolerate that.


def _load_payload(out_dir: Path) -> tuple[dict | None, list[str]]:
    path = out_dir / "clean_report.json"
    if not path.is_file():
        return None, [f"missing {path.name}"]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, [f"{path.name} did not parse: {exc}"]
    if not isinstance(payload, dict):
        return None, [f"{path.name} is not a JSON object"]
    return payload, []


def _check_json_exists(out_dir: Path, payload: dict | None) -> list[str]:
    return [] if payload is not None else [f"missing or unparsable {out_dir / 'clean_report.json'}"]


def _check_structure(out_dir: Path, payload: dict | None) -> list[str]:
    if payload is None:
        return []
    problems = []
    if not isinstance(payload.get("findings"), list):
        problems.append("payload['findings'] is not a list")
    if not isinstance(payload.get("metadata"), dict):
        problems.append("payload['metadata'] is not a dict")
    if not isinstance(payload.get("aggregates"), dict):
        problems.append("payload['aggregates'] is not a dict (taskf T-1.2)")
    return problems


def _check_aggregates(out_dir: Path, payload: dict | None) -> list[str]:
    if payload is None or not isinstance(payload.get("aggregates"), dict):
        return []
    problems = []
    agg = payload["aggregates"]
    consistency = agg.get("consistency")
    if not isinstance(consistency, dict) or not consistency.get("ok"):
        problems.append(
            "aggregates.consistency.ok is not true: %r"
            % (consistency.get("failing") if isinstance(consistency, dict)
               else consistency)
        )
    counts = agg.get("counts") if isinstance(agg.get("counts"), dict) else {}
    findings = payload.get("findings")
    if isinstance(findings, list) and "sast_records" in counts:
        if counts["sast_records"] != len(findings):
            problems.append(
                "aggregates.counts.sast_records=%r != len(findings)=%d"
                % (counts["sast_records"], len(findings))
            )
    if isinstance(findings, list) and "total_reported" in counts:
        # total_reported = sast + vulnerable SCA packages; SCA comes from
        # payload['sbom'], so recompute rather than assume.
        sbom = payload.get("sbom") if isinstance(payload.get("sbom"), list) else []
        from core import report_aggregates as _ra  # local: keeps import cost off module load
        vulnerable = sum(1 for p in sbom if _ra._is_vulnerable_package(p))
        expected = len(findings) + vulnerable
        if counts["total_reported"] != expected:
            problems.append(
                "aggregates.counts.total_reported=%r != len(findings)+vulnerable=%d"
                % (counts["total_reported"], expected)
            )
    return problems


def _check_filter_trace(out_dir: Path, payload: dict | None) -> list[str]:
    """FND-01: the payload carries its drop ledger and the arithmetic holds."""
    if payload is None:
        return []
    problems = []
    trace = payload.get("filter_trace")
    if trace is None:
        problems.append(
            "payload lacks filter_trace (FND-01: every discard is on the payload)"
        )
        return problems
    if not isinstance(trace, list):
        return ["payload['filter_trace'] is not a list"]
    for i, entry in enumerate(trace):
        if not isinstance(entry, dict):
            problems.append(f"filter_trace[{i}] is not a dict")
            continue
        missing = TRACE_ENTRY_KEYS - set(entry)
        extra = set(entry) - TRACE_ENTRY_KEYS
        if missing:
            problems.append(
                f"filter_trace[{i}] missing keys: {sorted(missing)}")
        if extra:
            problems.append(
                f"filter_trace[{i}] has non-canonical keys: {sorted(extra)}")
    meta = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    raw = meta.get("raw_candidates")
    if not isinstance(raw, int):
        problems.append(
            "metadata.raw_candidates missing/not an int (FND-01 arithmetic)")
    else:
        # FND-05: regex_budget_exceeded entries are scan-integrity
        # notices, not population discards -- same partition as
        # filter_trace.attach_to_payload, so the audit and the payload
        # can never disagree about what counts.
        drops = [e for e in trace
                 if isinstance(e, dict)
                 and e.get("stage") != "regex_budget_exceeded"]
        findings = payload.get("findings")
        n_findings = len(findings) if isinstance(findings, list) else -1
        if len(drops) + n_findings != raw:
            problems.append(
                "FND-01 arithmetic breach: len(drops)=%d + "
                "len(findings)=%d != raw_candidates=%d"
                % (len(drops), n_findings, raw)
            )
    return problems


def _check_artifact(name: str) -> Check:
    def check(out_dir: Path, payload: dict | None) -> list[str]:
        path = out_dir / name
        if not path.is_file():
            return [f"missing {name}"]
        size = path.stat().st_size
        if size < MIN_ARTIFACT_BYTES:
            return [f"{name} is only {size} bytes (expected >= {MIN_ARTIFACT_BYTES})"]
        return []
    return check


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _check_baseline(out_dir: Path, payload: dict | None) -> list[str]:
    """FND-08: diff current artifacts against tests/fixtures/baseline/manifest.json."""
    manifest_path = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "baseline" / "manifest.json"
    if not manifest_path.is_file():
        return [f"baseline manifest missing: run python tools/baseline.py first "
                f"({manifest_path.name} not committed)"]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"baseline manifest did not parse: {exc}"]
    problems = []
    files = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(files, dict) or not files:
        return ["baseline manifest has no 'files' entries"]
    for name, meta in sorted(files.items()):
        current = out_dir / name
        if not current.is_file():
            problems.append(f"baseline file missing from scan output: {name}")
            continue
        if not isinstance(meta, dict) or "sha256" not in meta:
            problems.append(f"baseline manifest entry for {name} lacks sha256")
            continue
        actual = _sha256(current)
        if actual != meta["sha256"]:
            problems.append(
                f"{name}: sha256 {actual[:12]}… != baseline {str(meta['sha256'])[:12]}…")
    return problems


def _check_sast_identity(out_dir: Path, payload: dict | None) -> list[str]:
    """B8 (SAST overnight): stable SAST finding identity.

    Every reported SAST finding must carry the identity triple the rest
    of the system builds on (group_key, SARIF partialFingerprints, diff
    lifecycle): non-empty rule_id, a file, and a positive line. Validated
    against real artifacts before pinning (17 clean_report.json under
    data/outputs: 0 missing across 63 findings).
    """
    if payload is None or not isinstance(payload.get("findings"), list):
        return []
    problems = []
    for i, f in enumerate(payload["findings"]):
        if not isinstance(f, dict):
            continue
        rid = str(f.get("rule_id") or "").strip()
        file_v = str(f.get("file") or f.get("file_path") or "").strip()
        try:
            line = int(f.get("line"))
        except (TypeError, ValueError):
            line = 0
        if not rid:
            problems.append(f"finding[{i}]: empty rule_id (SAST identity)")
        if not file_v:
            problems.append(f"finding[{i}]: empty file (SAST identity)")
        if line < 1:
            problems.append(f"finding[{i}]: missing/invalid line (SAST identity)")
    return problems


def _check_sast_uid(out_dir: Path, payload: dict | None) -> list[str]:
    """B8 (Phase B Wave 1): stable finding UID integrity.

    Three invariants over the additive ``finding_uid`` surface:

    1. FORMAT -- every uid a finding carries matches the sole generator's
       pinned format ``^b3id1-[0-9a-f]{32}$``. Malformed values are
       flagged, never repaired (contract §3.4).
    2. SARIF AGREEMENT -- when the scan's ``Security_Report.sarif`` is
       present, its ``rsecopsxFindingUid/v1`` keys and the payload's
       well-formed finding uids agree both ways (no drift, no duplicates).
    3. DUPLICATES (R-7) -- the same uid on two distinct payload findings
       is an identity-assignment defect: both findings stay in the report
       and the gate FAILS; nothing is merged or silently accepted.

    Absence is not a breach: findings without a uid (pre-Phase-B
    artifacts) pass through untouched. Per contract §3.4 the audit scope
    is what a finding DOES carry, not what it lacks -- malformed values
    are the flagged class, absent values are the fall-through class.
    """
    if payload is None or not isinstance(payload.get("findings"), list):
        return []
    # local imports: keeps module load cheap (same pattern as AUD-003)
    from core.finding_identity import UID_RE
    from reporting.sarif_export import SARIF_UID_KEY
    problems = []
    findings = payload["findings"]
    seen: dict[str, list[int]] = {}
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        uid = f.get("finding_uid")
        if uid is None or str(uid).strip() == "":
            continue
        uid = str(uid)
        if not UID_RE.match(uid):
            problems.append(
                f"finding[{i}]: malformed finding_uid {uid!r} "
                "(expected ^b3id1-[0-9a-f]{32}$)")
            continue
        seen.setdefault(uid, []).append(i)
    for uid, idxs in sorted(seen.items()):
        if len(idxs) > 1:
            problems.append(
                f"duplicate finding_uid {uid} on findings {idxs} "
                "(R-7 identity-assignment defect: preserved, never merged)")
    sarif_path = out_dir / "Security_Report.sarif"
    if sarif_path.is_file():
        try:
            sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            problems.append(f"{sarif_path.name} did not parse: {exc}")
            sarif = None
        if isinstance(sarif, dict):
            keys: dict[str, int] = {}
            for run in sarif.get("runs") or []:
                results = run.get("results") if isinstance(run, dict) else None
                for res in results or []:
                    if not isinstance(res, dict):
                        continue
                    key = (res.get("partialFingerprints") or {}).get(SARIF_UID_KEY)
                    if key:
                        keys[str(key)] = keys.get(str(key), 0) + 1
            for uid in sorted(set(seen) - set(keys)):
                problems.append(
                    f"finding uid {uid} missing from {sarif_path.name} "
                    f"{SARIF_UID_KEY} keys (SARIF/payload identity drift)")
            for key in sorted(set(keys) - set(seen)):
                problems.append(
                    f"{sarif_path.name} {SARIF_UID_KEY} {key} matches no "
                    "payload finding uid (SARIF/payload identity drift)")
            for key, n in sorted(keys.items()):
                if n > 1:
                    problems.append(
                        f"{sarif_path.name} {SARIF_UID_KEY} {key} appears "
                        f"{n} times (duplicate uid, R-7 class)")
    return problems


def _check_verdict_consistency(out_dir: Path, payload: dict | None) -> list[str]:
    """B8: verdict consistency -- dispositions/verdicts use the closed
    vocabularies, and a suppression always explains itself (G1.5/B4
    acceptance: suppressed findings stay in the audit WITH their reason,
    never deleted, never silent)."""
    if payload is None or not isinstance(payload.get("findings"), list):
        return []
    from analysis.ufib_brain import DISPOSITIONS
    from accuracy.config import VERDICTS as ACC_VERDICTS
    problems = []
    for i, f in enumerate(payload["findings"]):
        if not isinstance(f, dict):
            continue
        disp = f.get("disposition")
        if disp is not None and str(disp) not in DISPOSITIONS:
            problems.append(
                f"finding[{i}]: disposition {disp!r} outside the UFIB "
                "vocabulary")
        acc = f.get("accuracy") if isinstance(f.get("accuracy"), dict) else {}
        verdict = acc.get("verdict")
        if verdict is not None and str(verdict) not in ACC_VERDICTS:
            problems.append(
                f"finding[{i}]: accuracy.verdict {verdict!r} outside the "
                "accuracy vocabulary")
        suppressed = (str(disp) == "SUPPRESSED"
                      or str(verdict).startswith("SUPPRESSED_"))
        if suppressed and not str(acc.get("reason") or "").strip():
            problems.append(
                f"finding[{i}]: suppressed without a recorded reason "
                "(suppression explainability)")
    return problems


#: Registered invariant checks, in printed order.  Later ftasks phases
#: append their own; nothing is removed (Appendix C rollback story).
CHECKS: list[tuple[str, str, Check]] = [
    ("AUD-001", "clean_report.json exists and parses", _check_json_exists),
    ("AUD-002", "payload structure (findings/metadata/aggregates)", _check_structure),
    ("AUD-003", "aggregates consistency + counts match payload", _check_aggregates),
    ("AUD-004", "FND-01 filter_trace on payload, arithmetic holds", _check_filter_trace),
    ("AUD-005", "Security_Report.pdf present and non-trivial", _check_artifact("Security_Report.pdf")),
    ("AUD-006", "Security_Report.xlsx present and non-trivial", _check_artifact("Security_Report.xlsx")),
    ("AUD-S01", "B8 stable SAST finding identity (rule_id/file/line)", _check_sast_identity),
    ("AUD-S02", "B8 verdict consistency (closed vocabularies)", _check_verdict_consistency),
    ("AUD-S03", "B8 stable finding uid (format/SARIF agreement/R-7 duplicates)", _check_sast_uid),
]


def _print_summary(payload: dict | None) -> None:
    if payload is None:
        print("summary: no payload")
        return
    findings = payload.get("findings")
    meta = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    trace = payload.get("filter_trace")
    agg = payload.get("aggregates") if isinstance(payload.get("aggregates"), dict) else {}
    counts = agg.get("counts") if isinstance(agg.get("counts"), dict) else {}
    print(
        "summary: findings=%s raw_candidates=%s filter_trace=%s "
        "total_reported=%s sast_records=%s"
        % (
            len(findings) if isinstance(findings, list) else "?",
            meta.get("raw_candidates", "-"),
            len(trace) if isinstance(trace, list) else "-",
            counts.get("total_reported", "-"),
            counts.get("sast_records", "-"),
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python tools/report_audit.py",
        description="Audit one scan output directory against every registered "
                    "invariant (ftasks test-policy command 3).",
    )
    parser.add_argument("out_dir", help="scan output directory (e.g. /tmp/r)")
    parser.add_argument(
        "--baseline", action="store_true",
        help="also diff artifact bytes against tests/fixtures/baseline/ "
             "(FND-08 manifest)",
    )
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir)
    violations: list[tuple[str, str]] = []

    if not out_dir.is_dir():
        print(f"VIOLATION AUD-000: output directory does not exist: {out_dir}")
        print("1 violation(s)")
        return 1

    payload, load_errors = _load_payload(out_dir)
    for msg in load_errors:
        # A missing/unparsable JSON is itself the AUD-001 failure; the
        # remaining structural checks are skipped rather than cascading.
        violations.append(("AUD-001", msg))

    for check_id, _desc, fn in CHECKS:
        if check_id == "AUD-001" and load_errors:
            continue  # already recorded above
        try:
            problems = fn(out_dir, payload)
        except Exception as exc:  # a crashing check is a breach, never a pass
            problems = [f"check crashed: {type(exc).__name__}: {exc}"]
        for msg in problems:
            violations.append((check_id, msg))

    if args.baseline:
        try:
            problems = _check_baseline(out_dir, payload)
        except Exception as exc:
            problems = [f"baseline check crashed: {type(exc).__name__}: {exc}"]
        for msg in problems:
            violations.append(("AUD-B01", msg))

    for check_id, msg in violations:
        print(f"VIOLATION {check_id}: {msg}")

    _print_summary(payload)
    if violations:
        print(f"{len(violations)} violation(s)")
        return 1
    print("0 violations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
