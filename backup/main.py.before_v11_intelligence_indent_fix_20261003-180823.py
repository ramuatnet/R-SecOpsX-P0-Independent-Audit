r"""
main.py  -  R-SecOpsX SAST v2.0  (branding: edit core/config.py)
"""
from __future__ import annotations
from datetime import datetime

import argparse
import json
import multiprocessing
import os
import re
import sys
import time
import threading
from pathlib import Path

from core.config import TOOL_NAME, TOOL_FULL
from core.path_utils import file_name, to_report_path
from core.finding_model import normalize_payload, build_rule_telemetry
from scanner.abom import generate_abom
from scanner.aibom import generate_aibom
from scanner.apibom import generate_apibom
from scanner.cbom import generate_cbom
from scanner.iac_kubernetes import scan_kubernetes
from scanner.iac_terraform import scan_terraform
from scanner.mlbom import generate_mlbom
from scanner.iac_docker import scan_docker
from scanner.compliance_mapper import enrich_compliance, compliance_summary
from scanner.package_intelligence import enrich_report_payload
from scanner.dependency_intelligence import enrich_dependency_intelligence, dependency_summary
from scanner.change_intelligence import enrich_report_payload_with_change_intelligence
from scanner.changed_line_security import enrich_changed_line_findings
from scanner.change_impact import enrich_change_impact
from scanner.security_change_graph import enrich_security_change_graph
from scanner.security_test_coverage import enrich_security_test_coverage
from scanner.pr_security_summary import enrich_pr_security_summary
from scanner.security_test_generator import generate_security_test_blueprints
from scanner.historical_finding_intelligence import enrich_historical_finding_intelligence
from scanner.malicious_package_intelligence import enrich_malicious_package_intelligence
from scanner.fix_patch_intelligence import enrich_fix_patch_intelligence
from scanner.pr_review_integration import enrich_pr_review_integration
from scanner.finding_lifecycle_intelligence import enrich_report_payload_with_finding_lifecycle
from scanner.undeclared_dependency_intelligence import enrich_report_payload_with_undeclared_dependencies
from scanner.secret_intelligence import (
    enrich_secret_intelligence,
    secret_intelligence_summary,
    apply_optional_live_secret_validation,
    scan_secret_intelligence,
)
from analysis.governance_signal_engine import derive_governance_signals
from analysis.executive_decision_engine import derive_executive_decision
from scanner.reachability import analyze_reachability
from analysis.framework_enrichment_engine import (
    enrich_framework_mappings,
    framework_mapping_summary,
)
from scanner.llm_security import scan_llm_file
from scanner.llm_context_precision import classify_findings
from scanner.advanced_ai_security import scan_advanced_ai_file
from scanner.sast import _skip
from scanner.analysis_context import (
    enrich_findings_context,
    load_analysis_context_config,
)
from analysis.vulnerability_age_engine import (
    enrich_vulnerability_age,
    vulnerability_age_summary,
)
from analysis.license_policy_engine import (
    enrich_license_policy,
    license_policy_summary,
)
from analysis.license_evidence_resolver import enrich_license_evidence
from analysis.epss_intelligence_engine import (
    enrich_epss_intelligence,
    epss_intelligence_summary,
)
from analysis.exploitability_decision_engine import (
    enrich_exploitability_decision,
    exploitability_summary,
)
from analysis.kev_intelligence_engine import (
    enrich_kev_intelligence,
    kev_intelligence_summary,
)
from analysis.legacy_protocol_engine import enrich_legacy_protocol_intelligence
from analysis.exposure_surface_engine import enrich_exposure_surface_intelligence
from analysis.supply_chain_trust_engine import enrich_supply_chain_trust
from analysis.runtime_artifact_integrity_engine import enrich_runtime_artifact_integrity
from analysis.data_flow_sensitivity_engine import enrich_data_flow_sensitivity
from analysis.data_flow_correlation_engine import enrich_data_flow_correlation
from analysis.identity_access_risk_engine import enrich_identity_access_risk
from analysis.identity_access_correlation_engine import enrich_identity_access_correlation
from analysis.auth_hardening_risk_engine import enrich_auth_hardening_risk
from analysis.auth_hardening_correlation_engine import enrich_auth_hardening_correlation
from analysis.ai_model_risk_engine import enrich_ai_model_risk
from analysis.business_logic_risk_engine import enrich_business_logic_risk
from analysis.business_logic_correlation_engine import enrich_business_logic_correlation
from analysis.crypto_misuse_engine import enrich_crypto_misuse
from analysis.secret_blast_radius_correlation_engine import enrich_secret_blast_radius_correlation
from analysis.api_abuse_risk_engine import enrich_api_abuse_risk
from analysis.api_abuse_engine import analyze_api_abuse
from analysis.security_control_coverage_engine import enrich_security_control_coverage
from analysis.release_readiness_engine import derive_release_readiness
from analysis.copyright_ip_compliance_engine import analyze_copyright_ip_compliance
from analysis.privacy_data_exposure_engine import enrich_privacy_data_exposure
from analysis.ioc_malware_intelligence_engine import enrich_ioc_malware_intelligence
from analysis.juice_shop_ground_truth import enrich_juice_shop_ground_truth

from analysis.sbom_inventory_engine import build_sbom_full_inventory
from analysis.license_matrix_engine import build_license_matrix
from analysis.dependency_lineage_engine import build_dependency_lineage


# -----------------------------------------------------------------------------
# Scan performance timing
# -----------------------------------------------------------------------------
_SCAN_TIMING = {
    "started_at": None,
    "start_perf": None,
    "current_stage": None,
    "current_stage_start": None,
    "stages": [],
}


def _timing_start_scan():
    now = time.time()
    _SCAN_TIMING["started_at"] = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    _SCAN_TIMING["start_perf"] = time.perf_counter()
    _SCAN_TIMING["current_stage"] = None
    _SCAN_TIMING["current_stage_start"] = None
    _SCAN_TIMING["stages"] = []


def _timing_wall_now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _timing_gap_from_previous_end(start_at):
    previous_end = _SCAN_TIMING.get("previous_stage_end_at")
    if not previous_end:
        return 0.0
    try:
        start_dt = datetime.strptime(start_at, "%Y-%m-%d %H:%M:%S.%f")
        end_dt = datetime.strptime(previous_end, "%Y-%m-%d %H:%M:%S.%f")
        return max(0.0, (start_dt - end_dt).total_seconds())
    except Exception:
        return 0.0


_HEARTBEAT_STATE = {
    "stop_event": None,
    "thread": None,
    "console_supported": False,
}


def _windows_console_write(text):
    """Write one heartbeat line in-place using the native Windows console API.

    If stdout is not a real Windows console (for example redirected/captured
    output), deliberately do not emit a carriage-return fallback because many
    PowerShell/capture environments turn that into scrolling output.
    """
    if os.name != "nt":
        return False

    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        if handle in (0, -1):
            return False

        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False

        class COORD(ctypes.Structure):
            _fields_ = [
                ("X", wintypes.SHORT),
                ("Y", wintypes.SHORT),
            ]

        class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
            _fields_ = [
                ("dwSize", COORD),
                ("dwCursorPosition", COORD),
                ("wAttributes", wintypes.WORD),
                ("srWindowLeft", wintypes.SHORT),
                ("srWindowTop", wintypes.SHORT),
                ("srWindowRight", wintypes.SHORT),
                ("srWindowBottom", wintypes.SHORT),
                ("dwMaximumWindowSize", COORD),
            ]

        info = CONSOLE_SCREEN_BUFFER_INFO()
        if not kernel32.GetConsoleScreenBufferInfo(
            handle, ctypes.byref(info)
        ):
            return False

        width = max(1, int(info.dwSize.X) - 1)
        rendered = str(text)[:width].ljust(width)

        pos = info.dwCursorPosition
        pos.X = 0
        if not kernel32.SetConsoleCursorPosition(handle, pos):
            return False

        written = wintypes.DWORD()
        if not kernel32.WriteConsoleW(
            handle,
            rendered,
            len(rendered),
            ctypes.byref(written),
            None,
        ):
            return False

        return True
    except Exception:
        return False


def _windows_console_clear():
    """Clear the heartbeat line without producing a newline."""
    if os.name != "nt":
        return False

    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        if handle in (0, -1):
            return False

        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False

        class COORD(ctypes.Structure):
            _fields_ = [
                ("X", wintypes.SHORT),
                ("Y", wintypes.SHORT),
            ]

        class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
            _fields_ = [
                ("dwSize", COORD),
                ("dwCursorPosition", COORD),
                ("wAttributes", wintypes.WORD),
                ("srWindowLeft", wintypes.SHORT),
                ("srWindowTop", wintypes.SHORT),
                ("srWindowRight", wintypes.SHORT),
                ("srWindowBottom", wintypes.SHORT),
                ("dwMaximumWindowSize", COORD),
            ]

        info = CONSOLE_SCREEN_BUFFER_INFO()
        if not kernel32.GetConsoleScreenBufferInfo(
            handle, ctypes.byref(info)
        ):
            return False

        pos = info.dwCursorPosition
        pos.X = 0
        if not kernel32.SetConsoleCursorPosition(handle, pos):
            return False

        width = max(1, int(info.dwSize.X) - 1)
        written = wintypes.DWORD()
        if not kernel32.WriteConsoleW(
            handle,
            " " * width,
            width,
            ctypes.byref(written),
            None,
        ):
            return False

        pos.X = 0
        kernel32.SetConsoleCursorPosition(handle, pos)
        return True
    except Exception:
        return False


def _format_heartbeat_text(stage, elapsed):
    bar = "################----------------"
    return (
        f"[{bar}] Scanning {stage} | "
        f"{_format_duration(elapsed)}"
    )


def _timing_start_heartbeat(stage, start_perf):
    # The worker thread calculates elapsed time only. It never writes stdout.
    _timing_stop_heartbeat()

    stop_event = threading.Event()
    _SCAN_TIMING["heartbeat_stop_event"] = stop_event

    def _run():
        while not stop_event.wait(5.0):
            elapsed = time.perf_counter() - start_perf
            _HEARTBEAT_STATE["text"] = _format_heartbeat_text(
                stage,
                elapsed,
            )

            # Do not use print()/\\r here. A non-console fallback would scroll.
            _windows_console_write(_HEARTBEAT_STATE["text"])

    _HEARTBEAT_STATE["text"] = _format_heartbeat_text(
        stage,
        0.0,
    )
    _HEARTBEAT_STATE["console_supported"] = _windows_console_write(
        _HEARTBEAT_STATE["text"]
    )

    thread = threading.Thread(
        target=_run,
        name="rsecopsx-phase-heartbeat",
        daemon=True,
    )
    _SCAN_TIMING["heartbeat_thread"] = thread
    _HEARTBEAT_STATE["thread"] = thread
    thread.start()


def _timing_stop_heartbeat():
    # Stop the heartbeat and clear the native console line. No fallback print.
    stop_event = _SCAN_TIMING.pop("heartbeat_stop_event", None)
    thread = _SCAN_TIMING.pop("heartbeat_thread", None)

    if stop_event is not None:
        stop_event.set()

    if thread is not None and thread.is_alive():
        thread.join(timeout=0.2)

    if _HEARTBEAT_STATE.get("console_supported"):
        _windows_console_clear()

    _HEARTBEAT_STATE["text"] = ""
    _HEARTBEAT_STATE["console_supported"] = False
    _HEARTBEAT_STATE["thread"] = None

def _timing_close_stage():
    stage = _SCAN_TIMING.get("current_stage")
    start = _SCAN_TIMING.get("current_stage_start")
    start_at = _SCAN_TIMING.get("current_stage_start_at")
    if not stage or start is None:
        return

    end_at = _timing_wall_now()
    elapsed = time.perf_counter() - start
    _timing_stop_heartbeat()

    gap_seconds = _SCAN_TIMING.get("current_stage_gap_seconds", 0.0)
    _SCAN_TIMING["stages"].append({
        "stage": stage,
        "start_at": start_at or "N/A",
        "end_at": end_at,
        "seconds": round(elapsed, 4),
        "gap_seconds": round(float(gap_seconds), 4),
    })

    _safe_print(
        f"       [PHASE END] {stage} | END={end_at} | "
        f"ELAPSED={_format_duration(elapsed)} | "
        f"GAP_FROM_PREVIOUS_END={_format_duration(gap_seconds)}"
    )

    _SCAN_TIMING["previous_stage_end_at"] = end_at
    _SCAN_TIMING["current_stage"] = None
    _SCAN_TIMING["current_stage_start"] = None
    _SCAN_TIMING["current_stage_start_at"] = None
    _SCAN_TIMING["current_stage_gap_seconds"] = 0.0




def _timing_start_stage(label, heartbeat=True):
    _timing_close_stage()
    stage = str(label)
    start_at = _timing_wall_now()
    gap_seconds = _timing_gap_from_previous_end(start_at)

    _SCAN_TIMING["current_stage"] = stage
    _SCAN_TIMING["current_stage_start"] = time.perf_counter()
    _SCAN_TIMING["current_stage_start_at"] = start_at
    _SCAN_TIMING["current_stage_gap_seconds"] = gap_seconds

    _safe_print(
        f"       [PHASE START] {stage} | START={start_at} | "
        f"GAP_FROM_PREVIOUS_END={_format_duration(gap_seconds)}"
    )

    if heartbeat:
        _timing_start_heartbeat(
            _SCAN_TIMING["current_stage"],
            _SCAN_TIMING["current_stage_start"],
        )




def _format_duration(seconds):
    seconds = max(0.0, float(seconds))
    hours, rem = divmod(seconds, 3600.0)
    minutes, secs = divmod(rem, 60.0)
    if hours >= 1:
        return f"{int(hours):02d}:{int(minutes):02d}:{secs:05.2f}"
    return f"{int(minutes):02d}:{secs:05.2f}"


def _finish_scan_timing():
    _timing_close_stage()
    _timing_stop_heartbeat()
    start_perf = _SCAN_TIMING.get("start_perf")
    total = (time.perf_counter() - start_perf) if start_perf is not None else 0.0
    completed = _timing_wall_now()
    stages = list(_SCAN_TIMING.get("stages", []))

    _safe_print("")
    _safe_print("=" * 118)
    _safe_print("R-SecOpsX SCAN PERFORMANCE â€” DATE/TIME + PHASE GAP")
    _safe_print("=" * 118)
    _safe_print(f"SCAN START : {_SCAN_TIMING.get('started_at') or 'N/A'}")
    _safe_print("")
    _safe_print(
        f"  {'PHASE':<48} {'START':<23} {'END':<23} "
        f"{'ELAPSED':>11} {'GAP PREV END':>14}"
    )
    _safe_print("-" * 118)

    for item in stages:
        _safe_print(
            f"  {item['stage']:<48.48} "
            f"{item.get('start_at', 'N/A'):<23} "
            f"{item.get('end_at', 'N/A'):<23} "
            f"{_format_duration(item['seconds']):>11} "
            f"{_format_duration(item.get('gap_seconds', 0.0)):>14}"
        )

    _safe_print("-" * 118)
    _safe_print(f"  {'TOTAL SCAN TIME':<48} {_format_duration(total):>11}")
    _safe_print(f"SCAN END   : {completed}")
    _safe_print("=" * 118)

    return {
        "started_at": _SCAN_TIMING.get("started_at"),
        "completed_at": completed,
        "total_seconds": round(total, 4),
        "total_duration": _format_duration(total),
        "stages": stages,
    }





def classify_issue_group(finding: dict) -> str:
    vuln_type = str(finding.get("vuln_type", "")).lower()
    rule_id = str(finding.get("rule_id", "")).lower()
    title = str(finding.get("title", "")).lower()

    # Preserve IaC classification before generic credential/AI matching.
    if (
        vuln_type.startswith("k8s_")
        or vuln_type.startswith("tf_")
        or vuln_type.startswith("iac_")
        or vuln_type.startswith("docker_")
        or rule_id.startswith("k8s_")
        or rule_id.startswith("tf_")
        or rule_id.startswith("docker_")
    ):
        return finding.get("issue_group") or "Infrastructure / IaC"

    if vuln_type == "hardcoded_secret" or any(x in title for x in [
        "token", "secret", "password", "private key", "access key",
        "connection string", "credential", "jwt",
    ]):
        return "Credentials"

    if "crypto" in vuln_type or "hash" in title or "md5" in title or "sha1" in title:
        return "Crypto"

    if "ai" in vuln_type or "llm" in title or "openai" in title:
        return "AI"

    if "iac" in vuln_type or "terraform" in title or "container" in title:
        return "Infrastructure / IaC"

    if "sql" in vuln_type or "command" in vuln_type or "code_injection" in vuln_type:
        return "Injection"

    if "ssrf" in vuln_type:
        return "SSRF"

    if "deserialization" in vuln_type:
        return "Deserialization"

    if "debug" in vuln_type:
        return "Security Misconfiguration"

    if "api" in vuln_type:
        return "API Security"

    return "Application Security"


_HERE = Path(os.path.abspath(__file__)).parent
os.chdir(str(_HERE))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
os.environ["MPLBACKEND"] = "Agg"


def _is_path_within_root(path_value: str, target_root: str) -> bool:
    """Strict Windows/POSIX repository-boundary check.

    Uses realpath/commonpath in addition to pathlib so escaped relative paths
    (including ``..``), Windows paths on mixed hosts, junctions and symlinks
    cannot be accepted accidentally.
    """
    if not path_value:
        return True
    import os, ntpath
    try:
        root_s = os.path.realpath(os.path.abspath(str(target_root)))
        raw_s = str(path_value).strip()
        # Handle native absolute paths plus Windows absolute paths explicitly.
        if os.path.isabs(raw_s):
            candidate_s = os.path.realpath(raw_s)
            try:
                return os.path.commonpath([candidate_s, root_s]) == root_s
            except ValueError:
                return False
        if re.match(r"^[A-Za-z]:[\\/]", raw_s) or raw_s.startswith("\\\\"):
            candidate_s = ntpath.normpath(raw_s)
            root_nt = ntpath.normpath(str(target_root))
            try:
                return ntpath.commonpath([candidate_s.lower(), root_nt.lower()]) == root_nt.lower()
            except ValueError:
                return False
        norm = raw_s.replace('\\', os.sep).replace('/', os.sep)
        # Report paths commonly begin with <target-name>/.
        root_name = os.path.basename(os.path.normpath(root_s))
        if norm.split(os.sep, 1)[0].lower() == root_name.lower():
            candidate_s = os.path.realpath(os.path.join(os.path.dirname(root_s), norm))
        else:
            candidate_s = os.path.realpath(os.path.join(root_s, norm))
        return os.path.commonpath([candidate_s, root_s]) == root_s
    except Exception:
        return False


BENCHMARK_FIXTURE_MARKERS = (
    "/data/static/codefixes/",
    "\\data\\static\\codefixes\\",
)


def _is_benchmark_fixture_path(path_value: str) -> bool:
    """Identify packaged benchmark/code-fix fixtures rather than app code."""
    if not path_value:
        return False
    p = str(path_value).replace("\\", "/").lower()
    return "/data/static/codefixes/" in p or p.endswith("/data/static/codefixes")


def _filter_benchmark_fixtures(findings: list[dict], include_fixtures: bool = False) -> tuple[list[dict], int]:
    """Exclude benchmark fixture findings from normal production scans.

    Fixtures can physically live inside a target repository, so this gate is
    intentionally separate from the repository-boundary gate. Benchmark runs
    can opt in with --include-benchmark-fixtures.
    """
    if include_fixtures:
        return list(findings or []), 0
    kept = []
    dropped = 0
    for finding in findings or []:
        occs = finding.get("occurrences") or []
        if occs:
            valid_occs = []
            for occ in occs:
                candidates = (occ.get("full_path"), occ.get("absolute_path"), occ.get("file"), occ.get("file_path"))
                if any(_is_benchmark_fixture_path(v) for v in candidates if v):
                    dropped += 1
                    continue
                valid_occs.append(occ)
            if not valid_occs:
                continue
            finding["occurrences"] = valid_occs
            finding["instances"] = len(valid_occs)
            finding["occurrence_count"] = len(valid_occs)
            finding["affected_files"] = list(dict.fromkeys(o.get("file", "") for o in valid_occs if o.get("file")))
            kept.append(finding)
            continue
        candidates = (finding.get("full_path"), finding.get("absolute_path"), finding.get("file"), finding.get("file_path"))
        if any(_is_benchmark_fixture_path(v) for v in candidates if v):
            dropped += 1
            continue
        kept.append(finding)
    return kept, dropped


def _filter_findings_to_target(findings: list[dict], target_root: str) -> tuple[list[dict], int]:
    """Enforce repository scope at finding *and occurrence* level before scoring.

    Some engines group occurrences before the final report is built. A single
    out-of-scope occurrence must never survive inside an otherwise valid group.
    """
    kept = []
    dropped = 0
    for finding in findings or []:
        occs = finding.get("occurrences") or []
        if occs:
            valid_occs = []
            for occ in occs:
                full_candidate = occ.get("full_path") or occ.get("absolute_path")
                report_candidate = occ.get("file") or occ.get("file_path")
                if full_candidate and not _is_path_within_root(str(full_candidate), target_root):
                    dropped += 1
                    continue
                if report_candidate and not _is_path_within_root(str(report_candidate), target_root):
                    dropped += 1
                    continue
                valid_occs.append(occ)
            if not valid_occs:
                dropped += 1
                continue
            finding["occurrences"] = valid_occs
            finding["instances"] = len(valid_occs)
            finding["occurrence_count"] = len(valid_occs)
            finding["affected_files"] = list(dict.fromkeys(o.get("file", "") for o in valid_occs if o.get("file")))

        full_candidate = finding.get("full_path") or finding.get("absolute_path")
        report_candidate = finding.get("file") or finding.get("file_path")
        candidate = full_candidate or report_candidate
        if ((full_candidate and not _is_path_within_root(str(full_candidate), target_root))
                or (report_candidate and not _is_path_within_root(str(report_candidate), target_root))):
            # A grouped finding can have a stale top-level path while its
            # occurrence paths are valid. Prefer a valid occurrence anchor.
            valid_anchor = next((o.get("full_path") or o.get("file") for o in (finding.get("occurrences") or []) if o.get("full_path") or o.get("file")), None)
            if valid_anchor and _is_path_within_root(str(valid_anchor), target_root):
                finding["full_path"] = valid_anchor
            else:
                dropped += 1
                continue
        kept.append(finding)
    return kept, dropped


def _safe_print(text):
    try:
        print(text, flush=True)
    except UnicodeEncodeError:
        print(text.encode("ascii", errors="replace").decode("ascii"), flush=True)


def _banner():
    banner_title = f"{TOOL_FULL}  --  Security Scanner"
    line1 = f"|    {banner_title:<60}|"
    _safe_print(f"""
+--------------------------------------------------------------+
{line1}
|    SAST + SCA + Attack Path Correlation + Risk Scoring      |
+--------------------------------------------------------------+
""")


def _step(label, detail="", heartbeat=True):
    _timing_start_stage(label, heartbeat=heartbeat)
    msg = f"  >>  {label}"
    if detail:
        msg += f"  ({detail})"
    _safe_print(msg)

def _print_dist(dist):
    labels = {
        "Critical": "[CRIT]",
        "High": "[HIGH]",
        "Medium": "[MED] ",
        "Low": "[LOW] ",
        "Info": "[INFO]",
    }
    _safe_print("")
    _safe_print("  +--------------------------------------+")
    _safe_print("  |   SEVERITY DISTRIBUTION              |")
    _safe_print("  +--------------------------------------+")
    total = sum(int(dist.get(sev, 0) or 0) for sev in ["Critical", "High", "Medium", "Low", "Info"])
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        count = int(dist.get(sev, 0) or 0)
        pct = (100.0 * count / total) if total else 0.0
        bar = "#" * min(count, 20)
        _safe_print(f"  | {labels[sev]} {sev:<10}  {count:3d}  {pct:5.1f}%  {bar:<20} |")
    _safe_print("  +--------------------------------------+")
    _safe_print("")


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    seen = set()
    deduped = []

    for finding in findings:
        key = (
            finding.get("rule_id") or finding.get("vuln_type"),
            finding.get("file") or finding.get("file_path"),
            finding.get("line"),
            finding.get("snippet") or finding.get("evidence"),
        )

        if key in seen:
            continue

        seen.add(key)
        deduped.append(finding)

    return deduped



def _collect_secret_findings(findings: list[dict]) -> list[dict]:
    """
    Collect only secret-like findings for optional V4 live validation.

    This intentionally does not change the V3 finding schema. It only selects
    candidates after existing secret intelligence enrichment has completed.
    """
    secret_terms = (
        "secret",
        "credential",
        "api key",
        "apikey",
        "access key",
        "token",
        "password",
        "passwd",
        "pwd",
        "private key",
        "client secret",
        "connection string",
        "database url",
        "jdbc",
        "oauth",
        "jwt",
    )

    secret_vuln_types = {
        "hardcoded_secret",
        "secret_exposure",
        "jwt_secret",
        "connection_string",
        "oauth_client_secret",
        "database_connection_string",
        "database_connection_secret",
        "kafka_credential",
        "rabbitmq_credential",
        "spring_config_secret",
        "cloud_secret",
        "messaging_secret",
        "cloud_metadata_credential",
    }

    selected = []

    for finding in findings or []:
        if not isinstance(finding, dict):
            continue

        vuln_type = str(finding.get("vuln_type", "")).lower()
        if vuln_type in secret_vuln_types:
            selected.append(finding)
            continue

        haystack = " ".join(
            str(finding.get(k, ""))
            for k in (
                "rule_id",
                "title",
                "type",
                "secret_type",
                "description",
                "category",
                "issue_group",
                "snippet",
            )
        ).lower()

        if any(term in haystack for term in secret_terms):
            selected.append(finding)

    return selected


def _scan_llm_security(target: str) -> list[dict]:
    findings = []
    scan_ext = {
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".java", ".go", ".php", ".rb", ".cs",
        ".yml", ".yaml", ".json", ".txt", ".md",
        ".sh", ".ps1", ".bat"
    }

    skip_names = {
        "readme.md",
        "license.md",
        "changelog.md",
    }

    skip_parts = {
        "docs",
        "documentation",
        "examples",
        "tests",
        "test",
    }

    for path in Path(target).rglob("*"):
        if not path.is_file():
            continue

        # Reuse the centralized SAST exclusion policy so LLM analysis
        # does not scan dependency/build/generated trees such as node_modules.
        if _skip(path):
            continue

        if path.suffix.lower() not in scan_ext:
            continue

        name = path.name.lower()
        parts = {p.lower() for p in path.parts}

        if (
            name in skip_names
            or name.startswith("expected_")
            or "_expected" in name
            or name.endswith("_expected.json")
            or parts.intersection(skip_parts)
        ):
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            findings.extend(scan_llm_file(str(path), content))
        except Exception:
            continue

    return findings
    

def _apply_llm_context_precision(target: str, findings: list[dict]) -> tuple[list[dict], dict]:
    """Apply LLM context-precision classification to raw LLM findings."""
    if not findings:
        return [], {"raw": 0, "actionable": 0, "contextual": 0}

    file_cache = {}
    for path in Path(target).rglob("*"):
        if not path.is_file() or _skip(path):
            continue
        try:
            file_cache[str(path)] = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

    classified = classify_findings(findings, file_cache)
    actionable = [f for f in classified if f.get("actionable") is True]
    return actionable, {
        "raw": len(findings),
        "actionable": len(actionable),
        "contextual": len(classified) - len(actionable),
    }


def _scan_advanced_ai_security(target: str) -> list[dict]:
    findings = []
    scan_ext = {
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".java", ".go", ".php", ".rb", ".cs",
        ".yml", ".yaml", ".json", ".txt",
        ".sh", ".ps1", ".bat"
    }

    for path in Path(target).rglob("*"):
        if not path.is_file():
            continue

        # Reuse the centralized SAST exclusion policy here as well.
        if _skip(path):
            continue

        if path.suffix.lower() not in scan_ext:
            continue

        name = path.name.lower()
        parts = {p.lower() for p in path.parts}

        if (
            name.startswith("expected_")
            or "_expected" in name
            or parts.intersection({"docs", "documentation", "examples", "tests", "test"})
        ):
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            findings.extend(scan_advanced_ai_file(str(path), content))
        except Exception:
            continue

    return findings
    

def _normalize_finding_paths(payload: dict, target: str) -> None:
        for finding in payload.get("findings", []):
            original = finding.get("file", "")

            finding["full_path"] = finding.get("full_path") or original
            finding["file"] = to_report_path(original, target)
            finding["file_name"] = file_name(original)

            finding["issue_group"] = classify_issue_group(finding)
            finding["issue_type"] = finding.get("title", "")
            finding["file_path"] = finding.get("file", "")

            for occ in finding.get("occurrences", []):
                occ_original = occ.get("file", "")
                occ_full_original = occ.get("full_path") or occ_original

                # Preserve each occurrence's own absolute path. Previously grouped
                # findings inherited the first finding's full_path, which caused
                # cross-file evidence to point to the wrong source file.
                if ":" in str(occ_full_original) or str(occ_full_original).startswith("/"):
                    occ["full_path"] = occ_full_original
                elif ":" in str(occ_original) or str(occ_original).startswith("/"):
                    occ["full_path"] = occ_original
                elif ":" not in str(occ.get("full_path", "")):
                    occ["full_path"] = finding.get("full_path", occ_original)

                occ["file"] = to_report_path(occ_original, target)
                occ["file_name"] = file_name(occ_original)
                occ["file_path"] = occ.get("file", "")

            finding["affected_files"] = sorted({
                occ.get("file", "")
                for occ in finding.get("occurrences", [])
                if occ.get("file")
        })
        
def _drop_out_of_scope_occurrences(payload: dict, target: str) -> int:
    """Defense-in-depth: remove individual occurrences that resolve outside target.

    Grouped findings are never allowed to retain an out-of-repository occurrence.
    """
    removed = 0
    for finding in payload.get("findings", []):
        kept = []
        for occ in finding.get("occurrences") or []:
            candidate = occ.get("full_path") or occ.get("absolute_path") or occ.get("file")
            if candidate and not _is_path_within_root(str(candidate), target):
                removed += 1
                continue
            kept.append(occ)
        if kept:
            finding["occurrences"] = kept
            finding["instances"] = len(kept)
            finding["occurrence_count"] = len(kept)
            finding["affected_files"] = list(dict.fromkeys(o.get("file", "") for o in kept if o.get("file")))
        else:
            finding["occurrences"] = []
            finding["instances"] = 0
            finding["occurrence_count"] = 0
            finding["affected_files"] = []
    return removed


def _prune_unsupported_occurrences(payload: dict) -> int:
    """Remove grouped occurrences whose own evidence does not support the finding.

    Root-cause grouping is presentation-only. Each occurrence carries its own
    taint path/detection metadata so a validated occurrence cannot lend evidence
    to a separate static/configuration occurrence.
    """
    import re
    removed = 0
    for finding in payload.get("findings", []):
        occs = finding.get("occurrences") or []
        if not occs:
            continue
        vt = str(finding.get("vuln_type", "")).lower()
        kept = []
        for occ in occs:
            text = str(occ.get("snippet", "") or "")
            low = text.lower()
            taint = str(occ.get("taint_path", "") or "").lower()
            detection = str(occ.get("detection", "") or "").upper()
            supported = True

            if vt == "path_traversal":
                # A taint-validated occurrence is authoritative. Otherwise a
                # literal/static path read must not inherit another occurrence's taint.
                # Literal string paths are trusted/static for this rule and must
                # not inherit taint from another occurrence in the grouped finding.
                if re.search(r"(?:readFile|writeFile|appendFile|createReadStream|createWriteStream)\s*\(\s*['\"]", text, re.I):
                    supported = False
                else:
                    supported = bool("->" in taint and re.search(r"(?:file|path|filename|dest|target|name)", low))
                    if not supported and re.search(r"fs\.(?:read|write|append)|readfile|writefile|createwritestream", low):
                        supported = bool(re.search(r"(?:filePath|filename|fileName|dest|target|user.*path|path\s*=)", low))

            elif vt == "ssrf":
                # Require occurrence-local source-to-sink evidence. Configured
                # service URLs (LLM/base/environment URLs) are not user-input SSRF.
                supported = bool("->" in taint and re.search(r"(?:fetch|axios|http|request|urlopen|curl)", low))
                if re.search(r"(?:llmapiurl|baseurl|process\.env|configured|environment)", low):
                    supported = False

            elif vt == "hardcoded_secret":
                # Test specifications and explicit testing placeholders are not
                # production credential exposure. Keep real key material and
                # non-test data files eligible for secret findings.
                ofile = str(occ.get("file", "")).lower()
                if (
                    re.search(r"\.(?:spec|test)\.(?:js|ts|tsx|jsx)$", ofile)
                    or re.search(r"(?:testingpassword|test@test\.com)", low)
                    or re.search(r"(?:^|/)data/static/(?:users|fixtures|test-data)(?:\.|/)", ofile)
                    or re.search(r"(?:^|/)(?:fixtures?|seed(?:s)?|test-data)(?:/|\.)", ofile)
                ):
                    supported = False
                else:
                    supported = True

            elif vt == "insecure_deserialization":
                # Static repository-owned YAML/configuration does not prove
                # attacker-controlled deserialization.
                if (
                    re.search(r"yaml\.load\s*\(\s*(?:await\s+)?(?:fs\.)?readfile(?:sync)?\s*\(\s*", low)
                    or re.search(r"yaml\.load\s*\(\s*(?:await\s+)?readfile\s*\(\s*(?:file|path|filename)\b", low)
                ):
                    supported = False
                else:
                    supported = True

            elif vt == "code_injection":
                # Intentional dynamic-import compatibility shim; not attacker-
                # controlled evaluation. Keep actual eval/user-input Function cases.
                if re.search(r"new\s+function.*specifier.*return\s+import\(specifier\)", low, re.I):
                    supported = False

            elif "nosql" in vt:
                # Mongo/NoSQL API names alone do not prove injection. Require
                # operator/query construction or occurrence-local taint.
                supported = bool(
                    ("->" in taint and re.search(r"(?:find|findone|update|delete|collection)", low))
                    or re.search(r"\$(?:where|regex|ne|gt|gte|lt|lte|in|nin)\b", low)
                    or re.search(r"(?:find|findone)\s*\([^)]*(?:req\.|request\.|body|query|params)", low)
                )

            elif vt == "mass_assignment":
                supported = bool(
                    "->" in taint
                    or re.search(r"(?:req\.body|request\.body|\.\.\.\s*(?:req\.body|request\.body|body|payload))", low)
                )

            if supported:
                kept.append(occ)
            else:
                removed += 1

        if kept:
            finding["occurrences"] = kept
            finding["affected_files"] = list(dict.fromkeys(o.get("file", "") for o in kept if o.get("file")))
            finding["instances"] = len(kept)
        elif occs:
            # No occurrence satisfied its own evidence contract. Do not retain
            # an unsupported representative merely to keep the finding alive.
            finding["occurrences"] = []
            finding["affected_files"] = []
            finding["instances"] = 0
            finding["occurrence_count"] = 0
    return removed


def _apply_iac_metadata(payload: dict) -> None:
    metadata = payload.setdefault("metadata", {})

    metadata["k8s_findings"] = sum(
        1 for finding in payload.get("findings", [])
        if str(finding.get("rule_id", "")).startswith("K8S_")
    )

    metadata["tf_findings"] = sum(
        1 for finding in payload.get("findings", [])
        if str(finding.get("rule_id", "")).startswith("TF_")
    )

    metadata["docker_findings"] = sum(
        1 for finding in payload.get("findings", [])
        if str(finding.get("rule_id", "")).startswith("DOCKER_")
    )

    metadata["iac_findings"] = (
        metadata.get("k8s_findings", 0)
        + metadata.get("tf_findings", 0)
        + metadata.get("docker_findings", 0)
    )



def _canonicalize_dependency_artifacts(payload: dict) -> dict:
    """Prevent compound dependency constraints from being emitted as resolved versions."""
    for pkg in payload.get("sbom", []) or []:
        if not isinstance(pkg, dict):
            continue
        raw = str(pkg.get("version") or "").strip()
        if "||" in raw:
            pkg["version_constraint"] = raw
            pkg["version"] = "UNRESOLVED"
            pkg.pop("purl", None)
    return payload


def _final_report_integrity_pass(payload: dict) -> dict:
    """Final report contract pass immediately before serialization.

    After all enrichment/mapping stages, occurrences are the sole source of
    truth for occurrence-derived fields. This pass deliberately runs at the
    serialization boundary so later enrichers cannot reintroduce stale counts
    or evidence from pre-pruned grouped detections.
    """
    findings = []
    for finding in payload.get("findings", []):
        if not isinstance(finding, dict):
            continue
        raw_occs = finding.get("occurrences") or []
        cleaned = []
        seen = set()
        for occ in raw_occs:
            if not isinstance(occ, dict):
                continue
            file_value = str(occ.get("file") or occ.get("file_path") or occ.get("full_path") or "")
            line_value = occ.get("line")
            snippet = str(occ.get("snippet") or occ.get("evidence") or "")
            key = (file_value, line_value, snippet)
            if key in seen:
                continue
            seen.add(key)
            item = dict(occ)
            item["file"] = file_value
            item["file_path"] = str(item.get("file_path") or file_value)
            item["full_path"] = str(item.get("full_path") or file_value)
            item.setdefault("file_name", file_value.replace("\\", "/").split("/")[-1])
            cleaned.append(item)

        if not cleaned:
            continue

        finding["occurrences"] = cleaned
        files = list(dict.fromkeys(o["file"] for o in cleaned if o.get("file")))
        finding["affected_files"] = files
        finding["instances"] = len(cleaned)
        finding["occurrence_count"] = len(cleaned)
        finding["unique_file_count"] = len(files)
        finding["file_count"] = len(files)

        # Representative fields must come from a retained occurrence.
        rep = cleaned[0]
        for key in ("file", "file_path", "full_path", "file_name", "line", "snippet",
                    "taint_path", "detection", "sink_category"):
            value = rep.get(key)
            if value not in (None, ""):
                finding[key] = value

        # Final canonical sink taxonomy. Occurrence metadata can be stale after
        # deduplication/enrichment; weak-crypto findings must remain crypto,
        # not inherit unrelated model-binding/mass-assignment categories.
        try:
            vt = str(finding.get("vuln_type") or "").lower()
            rid = str(finding.get("rule_id") or "").upper()
            if vt == "weak_crypto" or "MD5_USAGE" in rid or "SHA1" in rid:
                finding["sink_category"] = "crypto"
            elif vt == "mass_assignment":
                finding["sink_category"] = "model_binding"
        except Exception:
            pass

        # Rebuild evidence ONLY from retained occurrences.
        evidence = []
        for occ in cleaned:
            for key in ("evidence", "snippet", "taint_path", "detection"):
                value = occ.get(key)
                values = value if isinstance(value, (list, tuple)) else [value]
                for v in values:
                    text = str(v or "").strip()
                    if text and text not in evidence:
                        evidence.append(text)
        finding["evidence"] = evidence

        # V17.9.1 canonical scoring pass: severity/exploitability are the
        # authoritative inputs and score factors must be regenerated from them
        # at the serialization boundary. This prevents stale factor values from
        # surviving later enrichment/deduplication.
        try:
            from core.risk_scorer import score_finding as _score_finding
            finding = _score_finding(finding)
        except Exception:
            pass

        # Keep validator evidence synchronized if present, but do not trust
        # stale validator evidence from before occurrence pruning.
        detail = finding.get("evidence_validation_detail")
        if isinstance(detail, dict):
            detail = dict(detail)
            detail["evidence"] = list(evidence)
            finding["evidence_validation_detail"] = detail

        findings.append(finding)

    payload["findings"] = findings

    # Recompute finding-level summaries from the final finding set.
    metadata = payload.setdefault("metadata", {})
    metadata["sast_findings"] = len(findings)
    from core.finding_model import normalize_payload as _normalize_payload
    payload = _normalize_payload(payload)
    metadata = payload.setdefault("metadata", metadata)
    metadata["sast_findings"] = len(findings)
    # Do not treat every SBOM package as a finding. Keep existing SCA count,
    # but make total_findings mathematically agree with the two components.
    sca_count = int(metadata.get("sca_findings", 0) or 0)
    metadata["total_findings"] = len(findings) + sca_count

    # Grouped SAST views must also reflect the final findings.
    try:
        from core.analyzer import group_by_severity, severity_distribution
        payload["grouped"] = group_by_severity(findings)
        sast_dist = severity_distribution(findings)

        # V17.9.1: make the declared combined distribution mathematically
        # represent SAST findings + unique vulnerable SBOM packages.
        combined_dist = dict(sast_dist)
        sca_dist = {sev: 0 for sev in ("Critical", "High", "Medium", "Low", "Info")}
        sca_unknown = 0
        for pkg in payload.get("sbom", []) or []:
            if not isinstance(pkg, dict):
                continue
            if not (pkg.get("vulnerabilities") or pkg.get("cve") or pkg.get("advisory_id")):
                continue
            sev = str(pkg.get("severity") or pkg.get("highest_vulnerability_severity") or "Unknown").title()
            if sev in sca_dist:
                sca_dist[sev] += 1
                combined_dist[sev] = combined_dist.get(sev, 0) + 1
            else:
                sca_unknown += 1

        metadata["severity_distribution"] = combined_dist
        metadata["severity_distribution_scope"] = "SAST_findings_plus_unique_vulnerable_dependency_packages"
        metadata["severity_distribution_sast"] = sast_dist
        metadata["severity_distribution_sca"] = sca_dist
        metadata["severity_distribution_sca_unknown"] = sca_unknown
        metadata["severity_distribution_unknown"] = sca_unknown

        from core.risk_scorer import compute_portfolio_score
        # Recompute portfolio after the final canonical scoring pass.
        vulnerable_sbom = [x for x in (payload.get("sbom", []) or []) if isinstance(x, dict) and (x.get("vulnerabilities") or x.get("cve") or x.get("advisory_id"))]
        metadata["risk_score"] = compute_portfolio_score(findings + vulnerable_sbom)
    except Exception:
        pass

    # V17.9.1 canonical dedup metadata: recompute from the FINAL serialized
    # finding set after all enrichment, normalization, and occurrence pruning.
    # This prevents stale pre-finalization counts such as 69/174 from surviving
    # when the final payload contains a different root/occurrence set.
    final_root_count = len(findings)
    final_occurrence_count = sum(
        len(f.get("occurrences") or []) for f in findings if isinstance(f, dict)
    )
    metadata["dedup_root_count"] = final_root_count
    metadata["dedup_occurrence_count"] = final_occurrence_count
    metadata["dedup_ratio"] = (
        round(final_root_count / final_occurrence_count, 2)
        if final_occurrence_count else 1.0
    )
    metadata["dedup_ratio_semantics"] = "SAST_ROOT_FINDINGS_DIVIDED_BY_SAST_OCCURRENCES"

    return payload

def _cleanup_report_noise(payload: dict) -> None:
    empty_list_fields = {
        "owasp_api_top10_2023",
        "owasp_llm_top10",
        "capec",
        "d3fend",
        "nist_csf_2_0",
        "nist_800_53",
        "iso_27001_2022",
        "pci_dss",
        "soc2",
        "hipaa",
        "gdpr",
        "dpdp",
        "remediation",
        "cwe",
        "mitre_attack",
        "owasp_top10_2021",
        "aliases",
        "fixed_versions",
        "indicators",
        "evidence",
        "chains_to",
        "likely_assets",
        "route_params",
        "mapped_frameworks",
        "memory_detected",
        "global_indicators",
    }

    def _clean_node(node):
        if isinstance(node, dict):
            if (
                node.get("taint_chain") == []
                and node.get("detection") != "ENTERPRISE_MULTI_LANGUAGE_TAINT_V1"
            ):
                node.pop("taint_chain", None)

            for key in empty_list_fields:
                if node.get(key) == []:
                    node.pop(key, None)

            for value in list(node.values()):
                _clean_node(value)

        elif isinstance(node, list):
            for item in node:
                _clean_node(item)

    _clean_node(payload)



def _valid_report_value(value) -> bool:
    if value is None:
        return False
    text = str(value).strip()
    return bool(text) and text.lower() not in {"none", "null", "unknown", "n/a", "na", ""}


def _safe_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _classify_sca_applicability(pkg: dict) -> dict:
    """Classify advisory applicability without silently suppressing package vulnerabilities.

    Advisory text can contain conditional platform/dialect requirements.  We preserve the
    vulnerability record but expose that condition explicitly so risk/reporting layers do
    not imply universal applicability.
    """
    intel = pkg.get("vulnerability_intelligence") or []
    if not isinstance(intel, list):
        intel = []
    conditional = []
    for adv in intel:
        if not isinstance(adv, dict):
            continue
        text = " ".join(str(adv.get(k) or "") for k in ("summary", "details", "description")).lower()
        conditions = []
        if "dialect is set to `oracle`" in text or "dialect === 'oracle'" in text or "dialect is oracle" in text:
            conditions.append("oracle_dialect")
        # Generic conditional applicability: preserve advisory conditions such as
        # feature flags/configuration gates without assuming universal applicability.
        feature_flag = bool(re.search(r"\b(?:feature\s+flag|flag|configuration|config)\b.{0,100}\b(?:true|false|enabled|disabled|enable|disable|set)\b|\bonly\s+when\b.{0,120}\b(?:feature\s+flag|flag|config(?:uration)?)\b", text, re.I))
        if feature_flag:
            conditions.append("feature_or_configuration_gate")
        if conditions:
            conditional.append({
                "vulnerability_id": adv.get("cve") or adv.get("id") or adv.get("advisory_id"),
                "conditions": conditions,
                "status": "CONDITIONAL_APPLICABILITY_REQUIRES_VALIDATION",
            })
    if conditional:
        return {
            "status": "CONDITIONAL_APPLICABILITY_REQUIRES_VALIDATION",
            "conditional_advisories": conditional,
        }
    return {
        "status": "NO_CONDITIONAL_APPLICABILITY_SIGNAL",
        "conditional_advisories": [],
    }


def _normalize_fixed_version_fields(payload):
    # V17.9.25: canonical fixed-version representation at report boundary.
    no_fixed = 'No fixed version identified in current advisory dataset.'
    _re = __import__('re')

    def _flatten(value):
        if value is None:
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                yield from _flatten(item)
            return
        text = str(value).strip()
        if not text:
            return
        if text.lower() in {'unknown', 'none', 'null', 'n/a', 'na'}:
            return
        if text == no_fixed:
            yield no_fixed
            return
        for token in _re.split(r'[,;\r\n]+', text):
            token = token.strip()
            if token:
                yield token

    def _canonical(value):
        result = []
        seen = set()
        for token in _flatten(value) or ():
            key = token.casefold()
            if key not in seen:
                seen.add(key)
                result.append(token)
        return result

    def _normalize_record(record):
        if not isinstance(record, dict):
            return
        raw_versions = record.get('fixed_versions')
        raw_fixed_in = record.get('fixed_in')
        versions = _canonical(raw_versions)
        fixed_in_versions = _canonical(raw_fixed_in)
        if versions and fixed_in_versions:
            versions = _canonical(versions + fixed_in_versions)
        elif not versions:
            versions = fixed_in_versions
        if no_fixed in versions and len(versions) > 1:
            versions = [v for v in versions if v != no_fixed]
        if versions:
            record['fixed_versions'] = versions
            record['fixed_in'] = ', '.join(versions)
        elif raw_versions is not None or raw_fixed_in is not None:
            record['fixed_versions'] = [no_fixed]
            record['fixed_in'] = no_fixed
        for key in ('vulnerabilities', 'vulnerability_intelligence', 'advisories'):
            nested = record.get(key)
            if isinstance(nested, list):
                for item in nested:
                    if isinstance(item, dict):
                        _normalize_record(item)

    if not isinstance(payload, dict):
        return
    for pkg in payload.get('sbom', []) or []:
        if isinstance(pkg, dict):
            _normalize_record(pkg)

def _build_dependency_reporting_views(payload: dict) -> None:
    """Create stable report-facing dependency/CVE views without changing scanner findings."""
    _normalize_fixed_version_fields(payload)
    sbom = payload.get("sbom", []) or []
    for _pkg in sbom:
        if isinstance(_pkg, dict):
            _pkg["sca_applicability"] = _classify_sca_applicability(_pkg)

    cve_rows = []
    advisory_rows = []
    reachable_vulnerable = []
    not_observed_vulnerable = []

    for pkg in sbom:
        cves = pkg.get("cve_list") or ([] if not pkg.get("cve") else [pkg.get("cve")])
        advisories = pkg.get("advisory_ids") or ([] if not pkg.get("advisory_id") else [pkg.get("advisory_id")])
        primary_id = (
            pkg.get("primary_vulnerability_id")
            or pkg.get("cve")
            or pkg.get("advisory_id")
        )

        row = {
            "package": pkg.get("name"),
            "name": pkg.get("name"),
            "version": pkg.get("version"),
            "ecosystem": pkg.get("ecosystem"),
            "dependency_type": pkg.get("dependency_type"),
            "purl": pkg.get("purl"),
            "primary_vulnerability_id": primary_id,
            "cve": pkg.get("cve"),
            "cve_list": cves,
            "advisory_id": pkg.get("advisory_id"),
            "advisory_ids": advisories,
            "cvss": pkg.get("cvss"),
            "cvss_score": pkg.get("cvss_score", pkg.get("cvss")),
            "cvss_available": pkg.get("cvss_available", pkg.get("cvss") is not None),
            "severity": pkg.get("severity"),
            "fixed_in": pkg.get("fixed_in") or pkg.get("fixed_versions"),
            "fixed_versions": pkg.get("fixed_versions"),
            "published_date": pkg.get("published_date") or pkg.get("published"),
            "modified": pkg.get("modified"),
            "vulnerability_age_days": pkg.get("vulnerability_age_days"),
            "vulnerability_age": pkg.get("vulnerability_age"),
            "vulnerability_age_bucket": pkg.get("vulnerability_age_bucket"),
            "age_as_of": pkg.get("age_as_of"),
            "zero_day_status": pkg.get("zero_day_status"),
            "zero_day_method": pkg.get("zero_day_method"),
            "outbreak_status": pkg.get("outbreak_status"),
            "source_vulnerability_id": pkg.get("source_vulnerability_id"),
            "normalized_cve": pkg.get("normalized_cve"),
            "vulnerability_source": pkg.get("vulnerability_source"),
            "reachability_status": pkg.get("reachability_status"),
            "reachability_priority": pkg.get("reachability_priority"),
            "reachability_confidence": pkg.get("reachability_confidence"),
            "kev_status": pkg.get("kev_status"),
            "actively_exploited": pkg.get("actively_exploited"),
            "epss_score": pkg.get("epss_score"),
            "epss_bucket": pkg.get("epss_bucket"),
            "epss_priority": pkg.get("epss_priority"),
            "patch_urgency": pkg.get("patch_urgency"),
            "exploitability_decision": pkg.get("exploitability_decision"),
            "license": pkg.get("license"),
            "license_policy_decision": pkg.get("license_policy_decision"),
            "applicability": _classify_sca_applicability(pkg),
        }

        if _valid_report_value(primary_id) or cves or advisories:
            advisory_rows.append(row)

        for cve in cves:
            cve_row = dict(row)
            cve_row["cve"] = cve
            cve_rows.append(cve_row)

        if pkg.get("reachability_priority") == "REACHABLE_VULNERABLE":
            reachable_vulnerable.append(row)
        elif pkg.get("reachability_priority") == "NOT_OBSERVED_VULNERABLE":
            not_observed_vulnerable.append(row)

    def _dep_rank(item: dict) -> tuple:
        return (
            1 if item.get("kev_status") else 0,
            _safe_float(item.get("cvss")),
            _safe_float(item.get("epss_score")),
            1 if item.get("reachability_priority") == "REACHABLE_VULNERABLE" else 0,
        )

    payload["dependency_risk_register"] = sorted(advisory_rows, key=_dep_rank, reverse=True)
    payload["top_dependency_risks"] = payload["dependency_risk_register"][:25]
    payload["top_cves"] = sorted(cve_rows, key=_dep_rank, reverse=True)[:25]
    payload["reachable_vulnerable_packages"] = reachable_vulnerable
    payload["not_observed_vulnerable_packages"] = not_observed_vulnerable

    metadata = payload.setdefault("metadata", {})
    metadata["cve_count"] = len({r.get("cve") for r in cve_rows if _valid_report_value(r.get("cve"))})
    metadata["advisory_count"] = len({
        advisory
        for row in advisory_rows
        for advisory in (row.get("advisory_ids") or [])
        if _valid_report_value(advisory)
    })
    metadata["packages_with_cvss"] = sum(1 for row in advisory_rows if row.get("cvss") is not None)
    metadata["packages_missing_cvss"] = sum(1 for row in advisory_rows if row.get("cvss") is None)
    metadata["dependency_risk_register_count"] = len(advisory_rows)



# -----------------------------------------------------------------------------
# Final client-facing mapping normalization
# -----------------------------------------------------------------------------
FINAL_BUSINESS_IMPACT_BY_RULE = {
    "SPRING_SECURITY_CSRF_DISABLED": "Global CSRF disablement and broad permitAll rules can allow unauthorized state-changing requests, session abuse, and broken access-control outcomes.",
    "SPRING_SECURITY_BROAD_PERMITALL_EXPOSURE": "Broad permitAll exposure can make privileged routes reachable without authentication, increasing account takeover and unauthorized administration risk.",
    "SPRING_SECURITY_PERMITALL_EXPOSURE": "Broad permitAll exposure can make privileged routes reachable without authentication, increasing account takeover and unauthorized administration risk.",
    "MASS_ASSIGNMENT": "Mass assignment can let attackers set fields the UI never intended to expose, causing privilege escalation, tenant-boundary bypass, or business workflow abuse.",
    "SPRING_MVC_MASS_ASSIGNMENT": "Mass assignment can let attackers set privileged fields such as role, isAdmin, tenantId, account status, balance, or approval state.",
    "ASP_NET_MASS_ASSIGNMENT": "Overposting can let attackers set privileged model fields such as role, isAdmin, tenantId, account status, or approval state.",
    "GRAPHQL_INTROSPECTION_EXPOSURE": "GraphQL introspection in production can expose schema, object names, hidden mutations, and authorization-sensitive fields, accelerating API reconnaissance.",
    "GRAPHQL_RESOLVER_BOLA_IDOR": "A resolver that fetches objects by user-controlled IDs without ownership checks can expose or modify another user's or tenant's records.",
    "GRAPHQL_BOLA_IDOR": "GraphQL BOLA/IDOR can allow attackers to access unauthorized objects by changing IDs, tenant IDs, or resolver parameters.",
    "TENANT_ISOLATION_FAILURE": "Missing tenant-boundary enforcement can expose cross-tenant data, enable account takeover across tenants, and create severe confidentiality and compliance impact.",
    "PRIVILEGE_ESCALATION_INDICATOR": "Privilege escalation paths can allow a standard user or service to perform admin actions, modify roles, or bypass approval gates.",
    "WORKFLOW_BYPASS_INDICATOR": "Workflow bypass can allow unauthorized approval, state transition, duplicate action, refund, payment, coupon, or account changes outside the intended process.",
    "JAVA_REFLECTION_SET_ACCESSIBLE": "Reflection access override can bypass encapsulation and security checks, enabling unauthorized access to private fields or methods and weakening sandbox assumptions.",
    "DANGEROUS_REFLECTION_SETACCESSIBLE": "setAccessible(true) can bypass Java access controls and may support exploit chains where attacker-influenced class or method names are used.",
    "API_LOGIN_BRUTE_FORCE": "Login endpoints without rate limits or lockout protections can enable credential stuffing, brute force, account takeover, and authentication service degradation.",
    "API_OTP_BRUTE_FORCE": "OTP and MFA endpoints without throttling can enable OTP guessing, MFA bypass, and account takeover.",
    "API_PASSWORD_RESET_ABUSE": "Password reset endpoints without throttling can enable reset flooding, user enumeration, token spraying, and account recovery abuse.",
    "API_INVITE_ABUSE": "Invite endpoints without throttling can enable spam, account enumeration, and social-engineering abuse.",
    "API_COUPON_REPLAY": "Coupon or promotion endpoints without replay/idempotency controls can enable financial loss through repeated redemption or abuse automation.",
    "API_TOKEN_REFRESH_ABUSE": "Token refresh endpoints without throttling and reuse detection can enable token spray, session extension abuse, and account takeover persistence.",
    "API_PAYMENT_DUPLICATE_ACTION": "Payment or transfer endpoints without idempotency controls can enable duplicate charges, duplicate withdrawals, or transaction integrity failures.",
}

FINAL_COMPLIANCE_BY_RULE = {
    "TENANT_ISOLATION_FAILURE": {
        "pci_dss": "Req 7 / Req 8 - Access control and tenant data segregation",
        "nist": "AC-3 / AC-6 / SC-7",
        "nist_800_53": "AC-3 / AC-6 / SC-7",
        "iso27001": "A.5.15 / A.8.3 / A.8.20",
        "iso_27001": "A.5.15 / A.8.3 / A.8.20",
        "soc2": "CC6.1 / CC6.6 / CC7.2",
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-639",
        "mitre": "T1190",
    },
    "GRAPHQL_INTROSPECTION_EXPOSURE": {
        "pci_dss": "Req 6.2.4 - Secure API configuration",
        "nist": "CM-7 / AC-3 / SC-7",
        "nist_800_53": "CM-7 / AC-3 / SC-7",
        "iso27001": "A.8.9 / A.8.20",
        "iso_27001": "A.8.9 / A.8.20",
        "soc2": "CC6.6 / CC7.2",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-200",
        "mitre": "T1595",
    },
    "GRAPHQL_RESOLVER_BOLA_IDOR": {
        "pci_dss": "Req 7 / Req 8 - Access control",
        "nist": "AC-3 / AC-6 / SI-10",
        "nist_800_53": "AC-3 / AC-6 / SI-10",
        "iso27001": "A.5.15 / A.8.3 / A.8.20",
        "iso_27001": "A.5.15 / A.8.3 / A.8.20",
        "soc2": "CC6.1 / CC6.6",
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-639",
        "mitre": "T1190",
    },
    "JAVA_REFLECTION_SET_ACCESSIBLE": {
        "pci_dss": "Req 6.2.4 - Secure coding and unsafe reflection prevention",
        "nist": "SI-10 / CM-7 / SA-11",
        "nist_800_53": "SI-10 / CM-7 / SA-11",
        "iso27001": "A.8.28 / A.8.29",
        "iso_27001": "A.8.28 / A.8.29",
        "soc2": "CC7.1 / CC7.2",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-470",
        "mitre": "T1059",
    },
    "DANGEROUS_REFLECTION_SETACCESSIBLE": {
        "pci_dss": "Req 6.2.4 - Secure coding and unsafe reflection prevention",
        "nist": "SI-10 / CM-7 / SA-11",
        "nist_800_53": "SI-10 / CM-7 / SA-11",
        "iso27001": "A.8.28 / A.8.29",
        "iso_27001": "A.8.28 / A.8.29",
        "soc2": "CC7.1 / CC7.2",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-470",
        "mitre": "T1059",
    },
}


def _final_rule_key(finding: dict) -> str:
    text = " ".join([
        str(finding.get("rule_id", "")),
        str(finding.get("title", "")),
        str(finding.get("vuln_type", "")),
    ]).upper().replace("-", "_").replace(" ", "_").replace("/", "_")

    if "TENANT_ISOLATION" in text:
        return "TENANT_ISOLATION_FAILURE"
    if "GRAPHQL" in text and ("INTROSPECTION" in text or "__SCHEMA" in text):
        return "GRAPHQL_INTROSPECTION_EXPOSURE"
    if "GRAPHQL" in text and ("BOLA" in text or "IDOR" in text or "RESOLVER" in text):
        return "GRAPHQL_RESOLVER_BOLA_IDOR"
    if "SETACCESSIBLE" in text or "SET_ACCESSIBLE" in text:
        return "JAVA_REFLECTION_SET_ACCESSIBLE"
    if "MASS_ASSIGNMENT" in text or "OVERPOSTING" in text:
        return "MASS_ASSIGNMENT"
    if "PERMITALL" in text or "PERMIT_ALL" in text:
        return "SPRING_SECURITY_BROAD_PERMITALL_EXPOSURE"
    if "CSRF" in text and "DISABLED" in text:
        return "SPRING_SECURITY_CSRF_DISABLED"
    if "LOGIN_BRUTE" in text or "API_LOGIN" in text:
        return "API_LOGIN_BRUTE_FORCE"
    if "OTP" in text or "MFA" in text:
        return "API_OTP_BRUTE_FORCE"
    if "PASSWORD_RESET" in text or "RESET_PASSWORD" in text or "FORGOT_PASSWORD" in text:
        return "API_PASSWORD_RESET_ABUSE"
    if "INVITE" in text or "INVITATION" in text:
        return "API_INVITE_ABUSE"
    if "COUPON" in text or "PROMO" in text or "REDEEM" in text or "VOUCHER" in text:
        return "API_COUPON_REPLAY"
    if "TOKEN_REFRESH" in text or "REFRESH_TOKEN" in text:
        return "API_TOKEN_REFRESH_ABUSE"
    if "PAYMENT" in text or "TRANSFER" in text or "IDEMPOTENCY" in text:
        return "API_PAYMENT_DUPLICATE_ACTION"
    return str(finding.get("rule_id", "")).upper()


def _is_empty_mapping(value) -> bool:
    text = str(value or "").strip().lower()
    return text in {"", "none", "null", "unknown", "n/a", "na", "not applicable"}



# ---------------------------------------------------------------------------
# V17.9.19 REPORT SAFETY / AUTHORITATIVE REMEDIATION
# ---------------------------------------------------------------------------
# Security findings may contain secrets as source evidence. The scanner must
# retain raw evidence internally for analysis, but report artifacts are an
# external trust boundary. Redaction therefore happens once, immediately
# before JSON/PDF/Excel/SARIF/VEX serialization.
_PEM_RE = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)* PRIVATE KEY-----",
    re.I | re.S,
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?P<prefix>\b(?:password|passwd|secret|client[-_ ]secret|api[-_ ]?key|access[-_ ]?key|private[-_ ]?key|jwt[-_ ]?secret|token)\b\s*[:=]\s*)(?P<quote>['\"]?)(?!\[REDACTED)(?P<value>[^\s,'\";]+)(?P<endquote>['\"]?)",
    re.I,
)

_SECRET_EVIDENCE_KEYS = {
    "snippet", "evidence", "evidence_snippet", "code_evidence", "sink_evidence",
    "source_expr", "sink_expr", "taint_path", "raw_evidence", "secret_value", "evidence_match",
}


def _infer_finding_language(finding: dict) -> str:
    lang = str(finding.get("language") or "").lower().strip()
    if lang:
        return lang
    suffix = Path(str(finding.get("file") or finding.get("file_path") or finding.get("full_path") or "")).suffix.lower()
    return {
        ".ts": "typescript", ".tsx": "typescript", ".js": "javascript", ".jsx": "javascript",
        ".py": "python", ".java": "java", ".go": "go", ".cs": "csharp", ".php": "php",
        ".tf": "terraform", ".json": "json", ".yaml": "yaml", ".yml": "yaml",
    }.get(suffix, "")


def _authoritative_remediation(finding: dict) -> list[str]:
    """Return the single report-facing remediation contract.

    The JSON payload is the canonical source for all downstream renderers.
    Prefer the hardened SAST resolver for language-sensitive rules, then fall
    back to report_mappings for rules that are intentionally language-neutral.
    """
    vuln = str(finding.get("vuln_type") or "").lower()
    title = str(finding.get("title") or "").lower()
    language = _infer_finding_language(finding)
    try:
        from scanner.sast import _remediation as sast_remediation
        from core.mapper import get_mapping
        from reporting.report_mappings import REMEDIATION_BY_RULE, rule_key
        mapping = get_mapping(vuln)
    except Exception:
        mapping = {}
        sast_remediation = None
        REMEDIATION_BY_RULE = {}
        rule_key = None

    # These rules already have authoritative, language-specific remediation
    # contracts in their producer scanners.  Resolve those contracts before the
    # generic SAST fallback so the fallback cannot mask them.  Keep this list
    # deliberately narrow to avoid changing remediation precedence globally.
    _producer_specific_rules = {
        "DOCKER_MISSING_USER",
        "LLM07_INSECURE_PLUGIN_DESIGN",
        "OAUTH_CLIENT_SECRET",
    }
    if rule_key is not None:
        try:
            _report_rule = rule_key(finding)
            if _report_rule in _producer_specific_rules:
                _mapped = REMEDIATION_BY_RULE.get(_report_rule)
                if _mapped:
                    return list(_mapped)
        except Exception:
            pass

    # Certain report-facing rules have authoritative, rule-specific guidance
    # that must take precedence over the generic SAST fallback. Keep this
    # allow-list intentionally narrow to avoid changing remediation precedence
    # for unrelated findings.
    try:
        from reporting.report_mappings import REMEDIATION_BY_RULE, rule_key
        report_rule = rule_key(finding)
        if report_rule in {"DOCKER_MISSING_USER", "LLM07_INSECURE_PLUGIN_DESIGN", "OAUTH_CLIENT_SECRET"}:
            mapped = REMEDIATION_BY_RULE.get(report_rule)
            if mapped:
                return list(mapped)
    except Exception:
        pass

    if vuln == "path_traversal" and language in {"javascript", "typescript"}:
        return [
            "Resolve the requested filename against a fixed base directory with path.resolve(baseDir, userPath).",
            "Verify path.relative(baseDir, resolvedPath) does not escape the base directory; reject absolute paths and traversal segments.",
            "Prefer server-generated file IDs instead of accepting raw filesystem paths from clients.",
            "Add regression tests for ../, encoded traversal, absolute paths, Windows-style traversal, and symlink escapes.",
        ]
    if vuln == "code_injection" and language in {"javascript", "typescript"}:
        return [
            "Remove eval(), new Function(), vm.runIn*(), or equivalent dynamic execution from request-controlled paths.",
            "Use JSON.parse() or a schema validator for data; do not turn input strings into executable JavaScript.",
            "If dynamic behavior is unavoidable, allow-list the supported operations and map them to fixed functions.",
            "Add regression tests proving crafted expressions are rejected and cannot execute code.",
        ]
    if vuln == "tf_open_security_group_ingress" or ("0.0.0.0/0" in title and language == "terraform"):
        return [
            "Restrict security-group ingress to approved source CIDRs instead of 0.0.0.0/0 for administrative or sensitive ports.",
            "If public access is required, allow only the required application port and approved source ranges; do not expose management ports to the Internet.",
            "Validate the Terraform plan and confirm no unintended 0.0.0.0/0 ingress rule remains after the change.",
            "Add IaC regression checks that fail when sensitive ports are exposed to 0.0.0.0/0 or ::/0.",
        ]
    if vuln == "llm_prompt_injection" or "prompt injection" in title:
        return [
            "Treat user-supplied and retrieved content as untrusted data and keep it structurally separate from system/developer instructions.",
            "Do not let model-generated text directly authorize privileged tool calls; enforce server-side authorization and least privilege for every tool action.",
            "Validate model outputs before executing commands, sending requests, changing records, or exposing sensitive context.",
            "Add adversarial regression tests for instruction override, indirect prompt injection, data exfiltration, and unauthorized tool use.",
        ]
    if vuln == "weak_crypto" and language in {"javascript", "typescript"}:
        return [
            "Replace MD5/SHA-1 with SHA-256 or SHA-3 for non-password hashing and integrity use cases.",
            "For password storage, use a password-hashing function such as Argon2id, bcrypt, or scrypt; never use MD5/SHA-1.",
            "For encryption, use an authenticated mode such as AES-256-GCM with keys managed outside source code.",
            "Add regression tests that reject deprecated algorithms in security-sensitive code paths.",
        ]
    if vuln == "supply_chain_script":
        return [
            "Review the preinstall/postinstall/prepare script and remove it if it is not required for the build or install process.",
            "Pin direct dependencies to reviewed versions and commit the lockfile; avoid * and latest ranges for security-sensitive builds.",
            "Run npm install/CI with a least-privileged build identity and disable lifecycle scripts where they are not required.",
            "Review package provenance and regenerate the SBOM after dependency changes.",
        ]
    if vuln == "insecure_deserialization" and language in {"javascript", "typescript"} and ("yaml" in title or "js-yaml" in title):
        return [
            "Upgrade js-yaml to a supported, non-vulnerable version and verify the lockfile resolves that version.",
            "Use the safe YAML schema/options supported by the installed js-yaml version; do not enable unsafe tags or JavaScript object construction for untrusted uploads.",
            "Validate the parsed YAML object against an expected schema before further processing.",
            "Add regression tests for malicious YAML tags, unexpected object types, oversized documents, and untrusted upload payloads.",
        ]
    if vuln == "nosql_injection":
        return [
            "If the flagged value is attacker-controlled, build a structured query from validated scalar values instead of dynamic query expressions.",
            "Allow-list accepted fields/operators and reject unexpected operators such as $where or $regex when they are not required.",
            "Do not pass request objects directly into database filters; construct the filter explicitly after validation.",
            "Add negative tests for operator injection, object-shaped parameters, regex abuse, and unexpected query fields.",
        ]
    if vuln == "api_abuse_missing_rate_limit":
        return [
            "Add a server-side rate limit appropriate to this endpoint: per-account and per-IP, and per-tenant where applicable.",
            "For login/OTP/reset flows, add progressive backoff and temporary blocking after repeated failures; do not rely on client-side throttling.",
            "For payment, checkout, coupon, and other duplicate-sensitive actions, require an idempotency key and enforce it in the server-side transaction.",
            "Return 429 when throttled, emit abuse metrics, and alert on repeated failures or abnormal request velocity.",
            "Add automated tests for burst traffic, replayed requests, duplicate submissions, and lockout/backoff behavior.",
        ]

    if sast_remediation is not None:
        try:
            # Do not feed legacy remediation back into the resolver. That is
            # exactly how the stale os.path.realpath/ast.literal_eval advice
            # previously survived into JSON.
            resolved = sast_remediation(vuln, mapping, None, language)
            if resolved:
                # Explicit report mappings must override ONLY the generic
                # SAST fallback. Preserve producer-specific SAST guidance.
                _generic = [
                    "Validate all user-controlled input at trust boundaries.",
                    "Use safe framework APIs and least privilege.",
                    "Add unit tests and security regression tests for this pattern.",
                ]
                try:
                    _report_rule = rule_key(finding) if rule_key is not None else None
                    _mapped = REMEDIATION_BY_RULE.get(_report_rule) if _report_rule else None
                    if _mapped and list(resolved) == _generic:
                        return list(_mapped)
                except Exception:
                    pass
                return list(resolved)
        except Exception:
            pass

    try:
        from reporting.report_mappings import REMEDIATION_BY_RULE, rule_key
        mapped = REMEDIATION_BY_RULE.get(rule_key(finding))
        if mapped:
            return list(mapped)
    except Exception:
        pass
    return list(finding.get("remediation") or [])


def _redact_secret_text(value: object) -> object:
    if not isinstance(value, str):
        return value
    text = _PEM_RE.sub("[REDACTED PRIVATE KEY]", value)
    # Only redact assignment-style secrets. This deliberately does not redact
    # arbitrary fields named 'value' because non-secret telemetry may use them.
    # Do not remask our own PEM marker.
    def _mask_assignment(match):
        if "[REDACTED PRIVATE KEY]" in str(match.group(0) or ""):
            return match.group(0)
        return f"{match.group('prefix')}{match.group('quote')}[REDACTED SECRET]{match.group('endquote')}"
    text = _SECRET_ASSIGNMENT_RE.sub(_mask_assignment, text)
    return text


def _redact_secret_evidence(node, secret_context: bool = False):
    if isinstance(node, list):
        return [_redact_secret_evidence(x, secret_context) for x in node]
    if isinstance(node, tuple):
        return tuple(_redact_secret_evidence(x, secret_context) for x in node)
    if isinstance(node, dict):
        is_secret_finding = (
            str(node.get("vuln_type") or "").lower() == "hardcoded_secret"
            or any(k in str(node.get("title") or "").lower() for k in ("secret", "private key", "credential", "password", "api key", "access key"))
        )
        out = {}
        for key, val in node.items():
            key_low = str(key).lower()
            child_secret = secret_context or is_secret_finding or key_low in _SECRET_EVIDENCE_KEYS
            if isinstance(val, str):
                # Evidence-bearing fields are always safe-redacted in secret
                # findings; PEM blocks are safe-redacted everywhere.
                # Apply the narrow assignment redactor globally as well as to
                # secret findings. This catches nested JSON-encoded intelligence
                # strings (for example crypto_misuse.evidence_match) without
                # globally removing benign telemetry fields such as data.value.
                out[key] = _redact_secret_text(val)
            else:
                out[key] = _redact_secret_evidence(val, child_secret)
        if is_secret_finding:
            out["evidence_redacted"] = True
            out["evidence_redaction_type"] = "REPORT_SECRET_VALUE_REDACTION"
        return out
    if isinstance(node, str):
        return _redact_secret_text(node)
    return node


def _apply_final_report_safety(payload: dict) -> dict:
    """Serialization-boundary contract for report integrity.

    1. Replaces stale/mismatched remediation in the canonical finding set.
    2. Calibrates actual PEM private-key findings to High/P2.
    3. Redacts secret material from findings and every nested report artifact.
    """
    findings = payload.get("findings", []) or []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        finding["remediation"] = _authoritative_remediation(finding)
        text = " ".join(str(finding.get(k) or "") for k in ("title", "vuln_type", "snippet", "evidence"))
        if str(finding.get("vuln_type") or "").lower() == "hardcoded_secret" and re.search(r"BEGIN(?: [A-Z0-9]+)* PRIVATE KEY", text, re.I):
            finding["severity"] = "High"
            finding["priority"] = "P2"
            finding["evidence_confidence"] = "HIGH"
            finding["context_confidence"] = "MEDIUM"
            finding["runtime_validation_status"] = "NOT_VALIDATED"
        finding["priority"] = {"Critical":"P1", "High":"P2", "Medium":"P3", "Low":"P4", "Info":"P4"}.get(str(finding.get("severity") or "Medium"), "P4")
        try:
            from core.risk_scorer import score_finding
            finding.update(score_finding(finding))
        except Exception:
            pass

    # Rebuild grouped output after remediation/severity normalization so every
    # renderer consumes the same canonical finding objects.
    try:
        from core.analyzer import group_by_severity
        payload["grouped"] = group_by_severity(findings)
    except Exception:
        payload["grouped"] = findings

    safe = _redact_secret_evidence(payload)
    metadata = safe.setdefault("metadata", {})
    metadata["report_evidence_redaction"] = {
        "enabled": True,
        "scope": "secret_and_private_key_evidence",
        "raw_analysis_evidence_retained_in_memory_only": True,
    }
    # Severity/risk fields are recalculated after final calibration so a
    # promoted private-key finding cannot leave stale distribution/risk values.
    try:
        from core.risk_scorer import compute_portfolio_score
        vulnerable_sbom = [
            p for p in (safe.get("sbom", []) or [])
            if isinstance(p, dict) and (p.get("vulnerabilities") or p.get("cve") or p.get("advisory_id"))
        ]
        metadata["risk_score"] = compute_portfolio_score(list(safe.get("findings", []) or []) + vulnerable_sbom)
    except Exception:
        pass
    dist = {sev: 0 for sev in ("Critical", "High", "Medium", "Low", "Info")}
    for finding in safe.get("findings", []) or []:
        sev = str(finding.get("severity") or "Info").title()
        if sev in dist:
            dist[sev] += 1
    for pkg in safe.get("sbom", []) or []:
        if not isinstance(pkg, dict) or not (pkg.get("vulnerabilities") or pkg.get("cve") or pkg.get("advisory_id")):
            continue
        sev = str(pkg.get("severity") or pkg.get("highest_vulnerability_severity") or "Unknown").title()
        if sev in dist:
            dist[sev] += 1
    # V17.9.20: rebuild ALL report statistics after final normalization.
    # This prevents stale pre-calibration SAST/SCA distributions.
    sast_dist = {sev: 0 for sev in ("Critical", "High", "Medium", "Low", "Info")}
    sca_dist = {sev: 0 for sev in ("Critical", "High", "Medium", "Low", "Info")}
    for finding in safe.get("findings", []) or []:
        sev = str(finding.get("severity") or "Info").title()
        if sev in sast_dist:
            sast_dist[sev] += 1
    vulnerable_packages = 0
    sca_unknown = 0
    for pkg in safe.get("sbom", []) or []:
        if not isinstance(pkg, dict) or not (pkg.get("vulnerabilities") or pkg.get("cve") or pkg.get("advisory_id")):
            continue
        vulnerable_packages += 1
        sev = str(pkg.get("severity") or pkg.get("highest_vulnerability_severity") or "Unknown").title()
        if sev in sca_dist:
            sca_dist[sev] += 1
        else:
            sca_unknown += 1
    metadata["severity_distribution_sast"] = sast_dist
    metadata["severity_distribution_sca"] = sca_dist
    metadata["severity_distribution_sca_unknown"] = sca_unknown
    metadata["severity_distribution_unknown"] = sca_unknown
    metadata["severity_distribution"] = {sev: sast_dist[sev] + sca_dist[sev] for sev in sast_dist}
    metadata["severity_distribution_scope"] = "SAST_findings_plus_unique_vulnerable_dependency_packages"
    metadata["sast_findings"] = len(safe.get("findings", []) or [])
    metadata["sca_findings"] = vulnerable_packages
    metadata["total_findings"] = metadata["sast_findings"] + vulnerable_packages
    try:
        from core.analyzer import group_by_severity, _top_root_causes
        safe["grouped"] = group_by_severity(list(safe.get("findings", []) or []))
        safe["top_root_causes"] = _top_root_causes(safe["grouped"])
    except Exception:
        pass
    return safe

def _apply_final_mapping_normalization(payload: dict) -> dict:
    findings = payload.get("findings", []) or []
    if not isinstance(findings, list):
        return payload

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        rule_key = _final_rule_key(finding)

        if rule_key in FINAL_BUSINESS_IMPACT_BY_RULE:
            finding["business_impact"] = FINAL_BUSINESS_IMPACT_BY_RULE[rule_key]

        comp = FINAL_COMPLIANCE_BY_RULE.get(rule_key)
        if comp:
            for key, value in comp.items():
                if _is_empty_mapping(finding.get(key)):
                    finding[key] = value

            controls = finding.setdefault("compliance_controls", {})
            if isinstance(controls, dict):
                if comp.get("owasp"):
                    controls["OWASP"] = [comp["owasp"]]
                if comp.get("cwe"):
                    controls["CWE"] = [comp["cwe"]]
                if comp.get("nist_800_53"):
                    controls["NIST 800-53"] = [x.strip() for x in comp["nist_800_53"].split("/")]
                if comp.get("pci_dss"):
                    controls["PCI DSS"] = [comp["pci_dss"]]
                if comp.get("iso_27001"):
                    controls["ISO 27001"] = [x.strip() for x in comp["iso_27001"].split("/")]
                if comp.get("soc2"):
                    controls["SOC 2"] = [x.strip() for x in comp["soc2"].split("/")]

        title = str(finding.get("title", "")).upper()
        vuln = str(finding.get("vuln_type", "")).upper()
        if rule_key == "TENANT_ISOLATION_FAILURE" or "TENANT_ISOLATION" in title or "TENANT_ISOLATION" in vuln:
            finding["issue_group"] = "Broken Access Control / Business Logic"
            if str(finding.get("framework", "")).lower() == "ai":
                finding["framework"] = "Application Security"
        elif "GRAPHQL" in title or "GRAPHQL" in vuln:
            finding["issue_group"] = "API Security / GraphQL"
            finding["framework"] = "graphql"
        elif "IDOR" in title or "BOLA" in title or vuln in {"IDOR", "BOLA"}:
            finding["issue_group"] = "Broken Access Control / Business Logic"

    return payload


def main():
    parser = argparse.ArgumentParser(description=TOOL_FULL)
    parser.add_argument(
        "target",
        nargs="?",
        default=str(_HERE / "sample_app"),
        help="Path to scan",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        default=None,
        help=(
            "Output directory. If omitted, reports are automatically saved as "
            "<target-parent>/reports/<project-name>/"
        ),
    )
    parser.add_argument(
        "--workers",
        "-w",
        type=int,
        default=2,
        help="Parallel workers (default 2)",
    )
    parser.add_argument("--no-pdf", action="store_true")
    parser.add_argument("--no-excel", action="store_true")
    parser.add_argument(
        "--include-benchmark-fixtures",
        action="store_true",
        help="Include packaged benchmark/code-fix fixtures such as data/static/codefixes in scan findings. Disabled by default.",
    )
    parser.add_argument(
        "--live-secrets",
        action="store_true",
        help="Enable optional live network validation of detected secrets. Disabled by default.",
    )
    parser.add_argument(
        "--live-secret-timeout",
        type=int,
        default=6,
        help="Timeout in seconds per live secret validation request. Default: 6.",
    )
    parser.add_argument(
        "--live-secret-max",
        type=int,
        default=50,
        help="Maximum number of detected secrets to live validate per scan. Default: 50.",
    )
    args = parser.parse_args()

    _banner()

    target_path = Path(os.path.abspath(args.target))
    target = str(target_path)

    if not os.path.exists(target):
        _safe_print(f"  [ERROR] Target path does not exist: {target}")
        sys.exit(2)

    if not os.path.isdir(target):
        _safe_print(f"  [ERROR] Target path is not a directory: {target}")
        sys.exit(2)

    # V17.9.x: project-isolated report output. By default every scan gets its
    # own directory under a sibling `reports` folder:
    #   <validation-root>/<project>/
    #   <validation-root>/reports/<project>/
    # This prevents one project's artifacts from overwriting another project's
    # reports. An explicit --output-dir/-o remains available as an override.
    project_name = target_path.name
    if args.output_dir:
        output_dir = Path(os.path.abspath(args.output_dir))
    else:
        output_dir = target_path.parent / "reports" / project_name
    output_dir.mkdir(parents=True, exist_ok=True)

    _safe_print(f"  Tool root : {_HERE}")
    _safe_print(f"  Project   : {project_name}")
    _safe_print(f"  Target    : {target}")
    _safe_print(f"  Output    : {output_dir}")
    _safe_print(f"  Workers   : {args.workers}")
    _safe_print("")

    t0 = time.time()
    _timing_start_scan()

    _step("Scanning codebase", f"regex + AST taint, {args.workers} workers")
    from scanner.sast import scan_directory

    raw = scan_directory(target, workers=args.workers)
    _safe_print(f"       => {len(raw)} raw findings in {time.time() - t0:.1f}s")

    _step("Generating SBOM & dependency analysis")
    from scanner.sbom import generate_sbom

    sbom = generate_sbom(target)

    # ------------------------------------------------------------------
    # Dependency Graph V2
    #
    # Only authoritative dependency relationships may become verified
    # graph edges. Existing SBOM package records are not modified.
    # ------------------------------------------------------------------
    dependency_graph = {
        "engine": "DEPENDENCY_GRAPH_V2",
        "graph_status": "NO_VERIFIED_EDGES",
        "verified_edge_count": 0,
        "edges": [],
        "evidence_policy": "AUTHORITATIVE_RELATIONSHIP_FIELDS_ONLY",
    }

    # The authoritative npm lockfile extractor is invoked only when a
    # package-lock.json is present. No relationship is inferred from
    # dependency_type, parent, introduced_by, or dependency_path.
    try:
        from analysis.npm_lock_graph_v2 import extract_verified_edges

        lockfiles = []

        for lockfile in Path(target).rglob("package-lock.json"):
            if not any(
                part in {"node_modules", ".git"}
                for part in lockfile.parts
            ):
                lockfiles.append(lockfile)

        graph_results = []

        for lockfile in lockfiles:
            try:
                graph_results.append(
                    extract_verified_edges(str(lockfile))
                )
            except Exception as exc:
                graph_results.append({
                    "engine": "NPM_LOCK_GRAPH_V2",
                    "source": str(lockfile),
                    "graph_status":
                        "EXTRACTION_ERROR",
                    "verified_edge_count": 0,
                    "edges": [],
                    "error": str(exc),
                })

        verified_edges = []

        for result in graph_results:
            for edge in result.get("edges", []) or []:
                if isinstance(edge, dict):
                    verified_edges.append(edge)

        if verified_edges:
            dependency_graph = {
                "engine": "DEPENDENCY_GRAPH_V2",
                "graph_status":
                    "VERIFIED_EDGES_AVAILABLE",
                "verified_edge_count":
                    len(verified_edges),
                "edges": verified_edges,
                "evidence_policy":
                    "AUTHORITATIVE_RELATIONSHIP_FIELDS_ONLY",
                "sources": [
                    result.get("source")
                    for result in graph_results
                    if result.get("source")
                ],
            }
        elif graph_results:
            dependency_graph = {
                "engine": "DEPENDENCY_GRAPH_V2",
                "graph_status":
                    "NO_VERIFIED_EDGES",
                "verified_edge_count": 0,
                "edges": [],
                "evidence_policy":
                    "AUTHORITATIVE_RELATIONSHIP_FIELDS_ONLY",
                "sources": [
                    result.get("source")
                    for result in graph_results
                    if result.get("source")
                ],
            }

        _safe_print(
            "       => Dependency graph: "
            f"{dependency_graph['verified_edge_count']} "
            "verified edges"
        )

    except Exception as exc:
        _safe_print(
            "       => Dependency graph unavailable; "
            f"preserving empty verified graph ({exc})"
        )

    vuln_deps = [d for d in sbom if d.get("cve")]
    vuln_deps = [d for d in sbom if d.get("cve")]
    _safe_print(f"       => {len(sbom)} packages, {len(vuln_deps)} with known CVEs")

    _step("Generating CBOM crypto inventory")
    cbom = generate_cbom(target)
    _safe_print(f"       => {len(cbom)} crypto assets identified")

    _step("Generating AI-BOM model/provider inventory")
    aibom = generate_aibom(target)
    _safe_print(f"       => {len(aibom)} AI assets identified")

    _step("Generating ML-BOM framework/model inventory")
    mlbom = generate_mlbom(target)
    _safe_print(f"       => {len(mlbom)} ML assets identified")

    _step("Generating API-BOM route inventory")
    apibom = generate_apibom(target)
    _safe_print(f"       => {len(apibom)} API routes identified")

    _step("Scanning API abuse controls")
    api_abuse_findings = []
    try:
        api_abuse_scan = analyze_api_abuse(target)
        if isinstance(api_abuse_scan, dict):
            api_abuse_findings = api_abuse_scan.get("api_abuse_findings", []) or []
        elif isinstance(api_abuse_scan, list):
            api_abuse_findings = api_abuse_scan
        _safe_print(f"       => {len(api_abuse_findings)} API abuse findings")
    except Exception as exc:
        _safe_print(f"       => API abuse scan failed: {exc}")

    _step("Generating ABOM agent inventory")
    abom = generate_abom(target)
    _safe_print(f"       => {len(abom)} AI agents identified")
    
    _step("Scanning OWASP LLM security rules")
    llm_raw_findings = _scan_llm_security(target)
    _safe_print(f"       => {len(llm_raw_findings)} raw OWASP LLM findings")

    llm_findings, llm_precision_stats = _apply_llm_context_precision(
        target,
        llm_raw_findings,
    )
    _safe_print(
        "       => LLM Context Precision: "
        f"{llm_precision_stats['actionable']} actionable | "
        f"{llm_precision_stats['contextual']} contextual/non-actionable"
    )
    
    _step("Scanning Advanced AI security rules")
    advanced_ai_findings = _scan_advanced_ai_security(target)
    _safe_print(f"       => {len(advanced_ai_findings)} Advanced AI findings")

    _step("Scanning Kubernetes IaC")
    k8s_findings = scan_kubernetes(target)
    _safe_print(f"       => {len(k8s_findings)} Kubernetes findings")

    _step("Scanning Terraform IaC")
    tf_findings = scan_terraform(target)
    _safe_print(f"       => {len(tf_findings)} Terraform findings")

    # --------------------------------------------------
    # Dockerfile IaC Analysis
    # --------------------------------------------------

    _step("Scanning Dockerfile IaC")
    docker_findings = scan_docker(target)
    _safe_print(f"       => {len(docker_findings)} Dockerfile findings")

    # --------------------------------------------------
    # Secret Intelligence Source Scan
    # V4 Phase 1 fix:
    # - V3 enrichment classified only existing findings.
    # - This explicitly adds scanner/secret_intelligence.py findings into raw.
    # - Live validation remains optional and is still controlled by --live-secrets.
    # --------------------------------------------------
    _step("Scanning Secret Intelligence")
    secret_scan_findings = []
    try:
        secret_scan_result = scan_secret_intelligence(target)
        if isinstance(secret_scan_result, dict):
            secret_scan_findings = secret_scan_result.get("secret_intelligence_findings", []) or []
        elif isinstance(secret_scan_result, list):
            secret_scan_findings = secret_scan_result
        _safe_print(f"       => {len(secret_scan_findings)} Secret Intelligence findings")
    except Exception as exc:
        _safe_print(f"       => Secret Intelligence scan failed: {exc}")

    _step("Deduplicating, scoring, correlating attack paths")

    raw.extend(k8s_findings)
    raw.extend(tf_findings)
    raw.extend(docker_findings)
    raw.extend(llm_findings)
    raw.extend(advanced_ai_findings)
    raw.extend(api_abuse_findings)
    raw.extend(secret_scan_findings)

    # Final defense-in-depth boundary: every engine must remain inside the
    # repository explicitly supplied by the user. This catches symlink/junction
    # escapes and third-party engine path-walking mistakes before scoring,
    # governance, SBOM correlation, or executive decisions.
    raw, dropped_benchmark_fixtures = _filter_benchmark_fixtures(
        raw, include_fixtures=args.include_benchmark_fixtures
    )
    if dropped_benchmark_fixtures:
        _safe_print(
            f"       => Benchmark fixture boundary dropped {dropped_benchmark_fixtures} fixture occurrences"
        )

    raw, dropped_outside_target = _filter_findings_to_target(raw, target)
    if dropped_outside_target:
        _safe_print(f"       => Intake boundary dropped {dropped_outside_target} out-of-scope findings")

    raw = _dedupe_findings(raw)

    # Canonical finding classification happens before downstream intelligence.
    raw = [normalize_payload({"findings": [f]})["findings"][0] for f in raw]

    from core.analyzer import build_report_payload


    # --------------------------------------------------
    # Analysis Context Classification
    # --------------------------------------------------
    # Classify findings after canonical normalization but before
    # report construction. This preserves benchmark evidence while
    # allowing synthetic findings to be excluded from primary
    # production-security counts according to config/analysis_context.yaml.
    raw = enrich_findings_context(
        raw,
        benchmark_profile="juice_shop",
        target_root=target,
    )

    _safe_print(
        "       => Analysis Context: "
        f"{sum(1 for f in raw if f.get('suppressed_from_primary_count'))} synthetic findings excluded from primary count | "
        f"{sum(1 for f in raw if f.get('preserved_for_evaluation'))} findings preserved for evaluation"
    )

    payload = build_report_payload(raw, sbom, target)

    # Dependency Graph V2 is a top-level payload artifact.
    # It is intentionally kept outside payload["sbom"] so existing
    # SCA/package processing remains unchanged.
    payload["dependency_graph"] = dependency_graph

    _normalize_finding_paths(payload, target)
    payload = normalize_payload(payload)
    payload["rule_telemetry"] = build_rule_telemetry(payload.get("findings", []))
    # Re-apply boundary after normalization because engines may emit escaped relative paths.
    _drop_out_of_scope_occurrences(payload, target)
    pruned_occurrences = _prune_unsupported_occurrences(payload)
    if pruned_occurrences:
        _safe_print(f"       => Occurrence evidence gate removed {pruned_occurrences} unsupported grouped occurrences")

    # Re-validate AFTER scope/evidence pruning. Earlier validation may have
    # inspected pre-group evidence arrays containing occurrences that are no
    # longer part of the finding. The final evidence state must describe only
    # retained occurrences.
    from core.analyzer import _apply_evidex_validation
    refreshed = []
    for _finding in payload.get("findings", []):
        if not _finding.get("occurrences"):
            continue
        refreshed.append(_apply_evidex_validation(_finding))
    payload["findings"] = refreshed
    payload["findings"] = [
        f for f in payload.get("findings", [])
        if int(f.get("instances", 0) or 0) > 0 and f.get("occurrences")
    ]
    _apply_iac_metadata(payload)
    payload = normalize_payload(payload)
try:
    from core.v11_intelligence import enrich_payload as _enrich_v11_intelligence
    payload = _enrich_v11_intelligence(payload)
except Exception as _v11_intelligence_error:
    payload.setdefault("v11_intelligence", {})["status"] = "REVIEW_REQUIRED"
    payload["v11_intelligence"]["error"] = str(_v11_intelligence_error)
    payload["rule_telemetry"] = build_rule_telemetry(payload.get("findings", []))

    # --------------------------------------------------
    # Compliance + Secret Intelligence
    # --------------------------------------------------
    _step("Compliance enrichment")
    payload["findings"] = enrich_compliance(payload.get("findings", []))
    payload["compliance_summary"] = compliance_summary(payload.get("findings", []))

    _step("Secret Intelligence enrichment")
    payload["findings"] = enrich_secret_intelligence(payload.get("findings", []))
    
    payload["secret_intelligence_summary"] = secret_intelligence_summary(
        payload.get("findings", [])
    )

    secret_validation_candidates = _collect_secret_findings(payload.get("findings", []))
    secret_live_summary = apply_optional_live_secret_validation(
        secret_validation_candidates,
        enabled=bool(args.live_secrets),
        timeout=max(1, int(args.live_secret_timeout)),
        max_validations=max(0, int(args.live_secret_max)),
    )

    payload["secret_live_validation_summary"] = secret_live_summary
    payload["secret_intelligence_summary"]["live_validation_mode"] = secret_live_summary.get(
        "mode",
        "OFFLINE_ONLY_NOT_VALIDATED",
    )
    payload["secret_intelligence_summary"]["live_validated_secrets"] = secret_live_summary.get(
        "live_valid",
        0,
    )
    payload["secret_intelligence_summary"]["live_validation_status"] = secret_live_summary.get(
        "status",
        "SECRET_LIVE_VALIDATION_DISABLED",
    )

    _safe_print(
        "       => Secret Live Validation: "
        f"{secret_live_summary.get('validated', 0)} validated | "
        f"{secret_live_summary.get('live_valid', 0)} live | "
        f"{secret_live_summary.get('not_valid_or_revoked', 0)} revoked/invalid | "
        f"{secret_live_summary.get('unsupported', 0)} unsupported | "
        f"{secret_live_summary.get('no_secret_value', 0)} no-value | "
        f"{secret_live_summary.get('inconclusive', 0)} inconclusive | "
        f"{secret_live_summary.get('errors', 0)} errors | "
        f"{secret_live_summary.get('status', 'SECRET_LIVE_VALIDATION_DISABLED')}"
    )

    _step("Secret blast-radius correlation")
    payload["secret_blast_radius_correlation_summary"] = enrich_secret_blast_radius_correlation(
        payload.get("findings", []),
        api_bom=payload.get("apibom", []),
        abom=payload.get("abom", []),
        aibom=payload.get("aibom", []),
    )
   
    _step("Framework mapping enrichment")
    payload["findings"] = enrich_framework_mappings(payload.get("findings", []))
    payload["framework_mapping_summary"] = framework_mapping_summary(
        payload.get("findings", [])
    )
    # --------------------------------------------------
    # BOM payload enrichment
    # --------------------------------------------------
    payload["cbom"] = cbom
    payload["aibom"] = aibom
    payload["mlbom"] = mlbom
    payload["apibom"] = apibom
    payload["abom"] = abom
    payload = enrich_report_payload(payload)

    # --------------------------------------------------
    # Dependency Intelligence -> Reachability -> Vulnerability Age
    # IMPORTANT: This order is required so later governance/executive
    # logic sees final dependency, reachability, and age intelligence.
    # --------------------------------------------------
    _step("Dependency intelligence")
    payload["sbom"] = enrich_dependency_intelligence(payload.get("sbom", []))
    dep_summary = dependency_summary(payload.get("sbom", []))
    payload["dependency_summary"] = dep_summary
    _step("Undeclared dependency intelligence")
    payload = enrich_report_payload_with_undeclared_dependencies(payload, target)

    _step("Reachability analysis")
    reachability_result = analyze_reachability(
        target,
        payload.get("sbom", [])
    )

    payload["sbom"] = reachability_result.get("sbom", payload.get("sbom", []))
    payload["reachability_summary"] = reachability_result.get("reachability_summary", {})
    payload["reachability_vulnerability_summary"] = reachability_result.get(
        "reachability_vulnerability_summary", {}
    )
    payload["reachability_references_count"] = reachability_result.get(
        "reachability_references_count", 0
    )

    _step("KEV intelligence")
    payload["sbom"] = enrich_kev_intelligence(payload.get("sbom", []))
    payload["kev_intelligence_summary"] = kev_intelligence_summary(
        payload.get("sbom", [])
    )

    _step("Vulnerability age intelligence")
    payload["sbom"] = enrich_vulnerability_age(payload.get("sbom", []))
    payload["vulnerability_age_summary"] = vulnerability_age_summary(
        payload.get("sbom", [])
    )
    
   

    _step("Legacy protocol intelligence")
    payload["sbom"], payload["legacy_protocol_summary"] = enrich_legacy_protocol_intelligence(
        payload.get("sbom", []),
        findings=payload.get("findings", []),
        cbom=payload.get("cbom", []),
        api_bom=payload.get("apibom", []),
    )

    _step("Exposure surface intelligence")
    payload["sbom"], payload["exposure_surface_summary"] = enrich_exposure_surface_intelligence(
        payload.get("sbom", []),
        findings=payload.get("findings", []),
        api_bom=payload.get("apibom", []),
        abom=payload.get("abom", []),
    )
    
    _step("EPSS intelligence")
    payload["sbom"] = enrich_epss_intelligence(payload.get("sbom", []))
    payload["epss_intelligence_summary"] = epss_intelligence_summary(
        payload.get("sbom", [])
    )
    
    _step("Exploitability decision")
    payload["sbom"] = enrich_exploitability_decision(payload.get("sbom", []))
    payload["exploitability_summary"] = exploitability_summary(
        payload.get("sbom", [])
    )
    
    _step("License evidence integration")
    payload = enrich_license_evidence(payload)
    _step("License policy")
    payload["sbom"] = enrich_license_policy(payload.get("sbom", []))
    payload["license_policy_summary"] = license_policy_summary(
        payload.get("sbom", [])
    )

    # Final license reporting aggregation:
    # preserve resolver evidence counts, while exposing policy-stage review state.
    _license_policy_summary = payload.get("license_policy_summary", {})
    _license_decision_counts = _license_policy_summary.get("decision_counts", {})

    _license_evidence_summary = payload.get("license_evidence_summary", {})
    _license_evidence_summary["policy_review_required_components"] = int(
        _license_decision_counts.get("REVIEW_REQUIRED", 0)
    )
    _license_evidence_summary["legal_review_required_components"] = int(
        _license_policy_summary.get("legal_review_required_components", 0)
    )
    _license_evidence_summary["unknown_license_components"] = int(
        _license_policy_summary.get("unknown_license_components", 0)
    )
    _license_evidence_summary["final_reporting_stage"] = "POST_LICENSE_POLICY"
    payload["license_evidence_summary"] = _license_evidence_summary
    _step("Copyright / IP compliance")
    payload["copyright_ip_compliance"] = analyze_copyright_ip_compliance(target)
    payload["copyright_ip_compliance_summary"] = payload["copyright_ip_compliance"].get(
        "summary", {}
    )
    
    
    
    _step("Supply-chain trust")
    payload["sbom"], payload["supply_chain_trust_summary"] = enrich_supply_chain_trust(
        payload.get("sbom", [])
    )
    
    _step("Runtime artifact integrity")
    payload["sbom"], payload["runtime_artifact_integrity_summary"] = enrich_runtime_artifact_integrity(
        payload.get("sbom", []),
        findings=payload.get("findings", []),
        abom=payload.get("abom", []),
        api_bom=payload.get("apibom", []),
    )
    
    _step("Data-flow sensitivity")
    payload["data_flow_sensitivity_summary"] = enrich_data_flow_sensitivity(
        payload.get("findings", []),
        api_bom=payload.get("apibom", []),
        abom=payload.get("abom", []),
    )
    
    correlation_input_findings = []
    correlation_input_findings.extend(payload.get("findings", []) or [])

    dfs = payload.get("data_flow_sensitivity_summary", {})

    if isinstance(dfs, dict):
        correlation_input_findings.extend(dfs.get("indicators", []) or [])
        correlation_input_findings.extend(dfs.get("findings", []) or [])
        correlation_input_findings.extend(dfs.get("sensitive_findings", []) or [])
        correlation_input_findings.extend(dfs.get("data_flow_indicators", []) or [])
        correlation_input_findings.extend(dfs.get("global_indicators", []) or [])

    _step("Data-flow correlation")
    payload["data_flow_correlation_summary"] = enrich_data_flow_correlation(
        correlation_input_findings,
        api_bom=payload.get("apibom", []),
        abom=payload.get("abom", []),
    )

    # --------------------------------------------------
    # Privacy + IOC / Backdoor Intelligence
    # --------------------------------------------------
    _step("Privacy data exposure")
    payload["privacy_data_exposure_summary"] = enrich_privacy_data_exposure(
        target,
        findings=payload.get("findings", []),
        api_bom=payload.get("apibom", []),
        data_flow_summary=payload.get("data_flow_sensitivity_summary", {}),
        live_progress=False,
    )

    _step("IOC / malware intelligence")
    payload["ioc_malware_intelligence_summary"] = enrich_ioc_malware_intelligence(
        target,
        findings=payload.get("findings", []),
        sbom=payload.get("sbom", []),
    )

    pds = payload.get("privacy_data_exposure_summary", {})
    iocs = payload.get("ioc_malware_intelligence_summary", {})

    payload["metadata"]["privacy_data_exposure_status"] = pds.get("summary_status", "NOT_AVAILABLE")
    payload["metadata"]["privacy_data_exposure_indicators"] = pds.get("total_privacy_indicators", 0)
    payload["metadata"]["privacy_data_exposure_critical"] = pds.get("critical_privacy_indicators", 0)
    payload["metadata"]["privacy_data_exposure_high"] = pds.get("high_privacy_indicators", 0)
    payload["metadata"]["privacy_third_party_transfer_indicators"] = pds.get("third_party_transfer_indicators", 0)
    # V17.9 privacy evidence semantics: raw matches, deduplicated findings,
    # and confirmed executive exposure are separate quantities.
    payload["metadata"]["privacy_raw_evidence_count"] = pds.get("raw_privacy_evidence_count", 0)
    payload["metadata"]["privacy_deduplicated_finding_count"] = pds.get("deduplicated_privacy_finding_count", 0)
    payload["metadata"]["privacy_potential_executive_review_indicators"] = pds.get("potential_executive_review_indicators", 0)
    payload["metadata"]["privacy_confirmed_executive_exposures"] = pds.get("confirmed_executive_exposures", 0)
    payload["metadata"]["privacy_static_exposure_indicators"] = pds.get("privacy_exposure_indicators", 0)
    payload["metadata"]["privacy_runtime_exposure_confirmed"] = pds.get("runtime_exposure_confirmed", 0)
    payload["metadata"]["privacy_classification_complete"] = pds.get("privacy_classification_complete", False)
    payload["metadata"]["privacy_unclassified_indicators"] = pds.get("privacy_unclassified_indicators", 0)

    payload["metadata"]["ioc_malware_status"] = iocs.get("summary_status", "NOT_AVAILABLE")
    payload["metadata"]["ioc_malware_indicators"] = iocs.get("total_ioc_indicators", 0)
    payload["metadata"]["ioc_malware_critical"] = iocs.get("critical_ioc_indicators", 0)
    payload["metadata"]["ioc_malware_high"] = iocs.get("high_ioc_indicators", 0)
    payload["metadata"]["ioc_malware_behavior_indicators"] = iocs.get("malware_behavior_indicators", 0)

    _safe_print(
        "       => Privacy Data Exposure: "
        f"{pds.get('total_privacy_indicators', 0)} indicators | "
        f"{pds.get('critical_privacy_indicators', 0)} critical | "
        f"{pds.get('high_privacy_indicators', 0)} high | "
        f"third-party {pds.get('third_party_transfer_indicators', 0)} | "
        f"{pds.get('summary_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => IOC / Backdoor Intelligence: "
        f"{iocs.get('total_ioc_indicators', 0)} indicators | "
        f"{iocs.get('critical_ioc_indicators', 0)} critical | "
        f"{iocs.get('high_ioc_indicators', 0)} high | "
        f"behavior {iocs.get('malware_behavior_indicators', 0)} | "
        f"{iocs.get('summary_status', 'NOT_AVAILABLE')}"
    )
    
    _step("Identity / access risk")
    payload["identity_access_risk_summary"] = enrich_identity_access_risk(
        payload.get("findings", []),
        api_bom=payload.get("apibom", []),
        abom=payload.get("abom", []),
        cbom=payload.get("cbom", []),
    )

    _step("Identity / access correlation")
    payload["identity_access_correlation_summary"] = enrich_identity_access_correlation(
        payload.get("findings", []),
        api_bom=payload.get("apibom", []),
        abom=payload.get("abom", []),
    )

    _step("Authentication hardening risk")
    payload["auth_hardening_risk_summary"] = enrich_auth_hardening_risk(
        payload.get("findings", []),
        api_bom=payload.get("apibom", []),
        target=target,
    )
    
    _step("Authentication hardening correlation")
    payload["auth_hardening_correlation_summary"] = enrich_auth_hardening_correlation(
        payload.get("auth_hardening_risk_summary", {}),
        api_bom=payload.get("apibom", []),
    )
    
    
    
    _step("AI model risk")
    payload["ai_model_risk_summary"] = enrich_ai_model_risk(
        payload.get("findings", []),
        aibom=payload.get("aibom", []),
        mlbom=payload.get("mlbom", []),
        abom=payload.get("abom", []),
    )



    _step("Business-logic risk")
    payload["business_logic_risk_summary"] = enrich_business_logic_risk(
        payload.get("findings", []),
        api_bom=payload.get("apibom", []),
        abom=payload.get("abom", []),
    )
    
    _step("API abuse risk")
    payload["api_abuse_risk_summary"] = enrich_api_abuse_risk(
        payload.get("findings", []),
        api_bom=payload.get("apibom", []),
    )

    _step("Business-logic correlation")
    payload["business_logic_correlation_summary"] = enrich_business_logic_correlation(
        payload.get("business_logic_risk_summary", {}),
        api_abuse_summary=payload.get("api_abuse_risk_summary", {}),
        api_bom=payload.get("apibom", []),
    )


    _step("Security control coverage")
    payload["security_control_coverage_summary"] = enrich_security_control_coverage(
        payload.get("findings", []),
        api_bom=payload.get("apibom", []),
        cbom=payload.get("cbom", []),
        abom=payload.get("abom", []),
        console_writer=_safe_print,
    )

    _step("Crypto misuse analysis")
    payload["crypto_misuse_summary"] = enrich_crypto_misuse(
        payload.get("findings", []),
        cbom=payload.get("cbom", []),
    )
    sis = payload.get("secret_intelligence_summary", {})
    reach = payload.get("reachability_summary", {})
    rv = payload.get("reachability_vulnerability_summary", {})
    vas = payload.get("vulnerability_age_summary", {})

    # --------------------------------------------------
    # Reachability-Aware Reporting Lists
    # --------------------------------------------------
    reachable_vulnerable_packages = []
    not_observed_vulnerable_packages = []

    for pkg in payload.get("sbom", []):
        item = {
            "name": pkg.get("name"),
            "version": pkg.get("version"),
            "dependency_type": pkg.get("dependency_type"),
            "cve": pkg.get("cve"),
            "license": pkg.get("license"),
            "reachability_status": pkg.get("reachability_status"),
            "reachability_priority": pkg.get("reachability_priority"),
            "reachability_confidence": pkg.get("reachability_confidence"),
            "reachability_confidence_label": pkg.get("reachability_confidence_label"),
            "reachability_method": pkg.get("reachability_method"),
            "reachability_evidence_type": pkg.get("reachability_evidence_type"),
            "published_date": pkg.get("published_date"),
            "vulnerability_age_days": pkg.get("vulnerability_age_days"),
            "vulnerability_age_bucket": pkg.get("vulnerability_age_bucket"),
            "kev_status": pkg.get("kev_status"),
            "actively_exploited": pkg.get("actively_exploited"),
            "outbreak_status": pkg.get("outbreak_status"),
            "patch_urgency": pkg.get("patch_urgency"),
        }

        if pkg.get("reachability_priority") == "REACHABLE_VULNERABLE":
            reachable_vulnerable_packages.append(item)

        elif pkg.get("reachability_priority") == "NOT_OBSERVED_VULNERABLE":
            not_observed_vulnerable_packages.append(item)

    payload["reachable_vulnerable_packages"] = reachable_vulnerable_packages
    payload["not_observed_vulnerable_packages"] = not_observed_vulnerable_packages

    # Stable CVE/CVSS/advisory views for PDF/XLS/SARIF/VEX/CycloneDX.
    _build_dependency_reporting_views(payload)
    reachable_vulnerable_packages = payload.get("reachable_vulnerable_packages", [])
    not_observed_vulnerable_packages = payload.get("not_observed_vulnerable_packages", [])

    # --------------------------------------------------
    # Fix Supply Chain insight using final reachability truth
    # --------------------------------------------------
    reachable_vuln = len(reachable_vulnerable_packages)

    updated_insights = []

    for insight in payload.get("insights", []):
        if insight.startswith("SUPPLY CHAIN:"):
            vuln_count = sum(
                1 for pkg in payload.get("sbom", [])
                if _safe_float(pkg.get("cvss")) >= 7.0
            )

            insight = (
                f"SUPPLY CHAIN: {vuln_count} dependency packages with CVSS >= 7.0 detected. "
                f"{reachable_vuln} vulnerable dependency packages have statically observed "
                "reachability evidence. This does not by itself prove runtime execution. Upgrade affected packages to patched "
                "versions before release."
            )

        updated_insights.append(insight)

    payload["insights"] = updated_insights


    # --------------------------------------------------
    # Governance Signals + Executive Decision
    # IMPORTANT: This must run after Secret Intelligence, Framework
    # Enrichment, Dependency Intelligence, Reachability, Vulnerability
    # Age, and reachability-aware reporting lists.
    # --------------------------------------------------
    governance_result = derive_governance_signals(payload)

    payload["governance_signals"] = governance_result.get("governance_signals", [])
    payload["governance_signal_summary"] = governance_result.get(
        "governance_signal_summary", {}
    )

    payload["release_readiness"] = derive_release_readiness(payload)

    executive_decision = derive_executive_decision(
        governance_result,
        payload.get("release_readiness", {}),
    )
    payload["executive_decision"] = executive_decision

    gss = payload.get("governance_signal_summary", {})
    ed = payload.get("executive_decision", {})
    rrs = payload.get("release_readiness", {})
    # --------------------------------------------------
    # Metadata Counters
    # --------------------------------------------------
    payload["metadata"]["secret_intelligence_total"] = sis.get("total_secrets", 0)
    payload["metadata"]["secret_high_blast_radius"] = sis.get("high_blast_radius", 0)
    payload["metadata"]["secret_critical_blast_radius"] = sis.get(
        "critical_blast_radius", 0
    )
    payload["metadata"]["secret_validation_status"] = sis.get(
        "validation_status", "OFFLINE_ONLY_NOT_VALIDATED"
    )
    sls = payload.get("secret_live_validation_summary", {})
    payload["metadata"]["secret_live_validation_enabled"] = sls.get("enabled", False)
    payload["metadata"]["secret_live_validation_status"] = sls.get(
        "status", "SECRET_LIVE_VALIDATION_DISABLED"
    )
    payload["metadata"]["secret_live_validation_mode"] = sls.get(
        "mode", "OFFLINE_ONLY_NOT_VALIDATED"
    )
    payload["metadata"]["secret_live_validated"] = sls.get("validated", 0)
    payload["metadata"]["secret_live_valid"] = sls.get("live_valid", 0)
    payload["metadata"]["secret_live_no_secret_value"] = sls.get("no_secret_value", 0)
    payload["metadata"]["secret_live_inconclusive"] = sls.get("inconclusive", 0)
    payload["metadata"]["secret_live_errors"] = sls.get("errors", 0)

    payload["metadata"]["direct_dependencies"] = dep_summary["direct_dependencies"]
    payload["metadata"]["transitive_dependencies"] = dep_summary["transitive_dependencies"]
    payload["metadata"]["unknown_dependencies"] = dep_summary["unknown_dependencies"]
    payload["metadata"]["vulnerable_direct_dependencies"] = dep_summary[
        "vulnerable_direct_dependencies"
    ]
    payload["metadata"]["vulnerable_transitive_dependencies"] = dep_summary[
        "vulnerable_transitive_dependencies"
    ]

    payload["metadata"]["reachable_packages"] = reach.get("reachable_packages", 0)
    payload["metadata"]["not_observed_packages"] = reach.get("not_observed_packages", 0)
    payload["metadata"]["unknown_reachability_packages"] = reach.get("unknown_packages", 0)
    payload["metadata"]["direct_reachable_packages"] = reach.get("direct_reachable", 0)
    payload["metadata"]["transitive_reachable_packages"] = reach.get(
        "transitive_reachable", 0
    )
    payload["metadata"]["reachability_references_count"] = payload.get(
        "reachability_references_count", 0
    )

    kis = payload.get("kev_intelligence_summary", {})
    vas = payload.get("vulnerability_age_summary", {})
    eis = payload.get("epss_intelligence_summary", {})
    exs = payload.get("exploitability_summary", {})
    lps = payload.get("license_policy_summary", {})
    cips = payload.get("copyright_ip_compliance_summary", {})
    lgs = payload.get("legacy_protocol_summary", {})
    ess = payload.get("exposure_surface_summary", {})
    scts = payload.get("supply_chain_trust_summary", {})
    rais = payload.get("runtime_artifact_integrity_summary", {})
    dfss = payload.get("data_flow_sensitivity_summary", {})
    dfcs = payload.get("data_flow_correlation_summary", {})
    iars = payload.get("identity_access_risk_summary", {})
    iacs = payload.get("identity_access_correlation_summary", {})
    ahrs = payload.get("auth_hardening_risk_summary", {})
    ahcs = payload.get("auth_hardening_correlation_summary", {})
    amrs = payload.get("ai_model_risk_summary", {})
    blrs = payload.get("business_logic_risk_summary", {})
    blcs = payload.get("business_logic_correlation_summary", {})

    # Canonicalize business-logic summary to correlation output when correlations
    # exist. This prevents stale standalone-engine severity/type counts from
    # contradicting the final correlation state.
    if blcs.get("total_business_logic_correlations", 0) > 0:
        blrs = dict(blrs)
        blrs["summary_status"] = "BUSINESS_LOGIC_RISK_IDENTIFIED_FROM_CORRELATION"
        blrs["total_business_logic_indicators"] = blcs.get("total_business_logic_correlations", 0)
        blrs["critical_business_logic_indicators"] = blcs.get("critical_business_logic_correlations", 0)
        blrs["high_business_logic_indicators"] = blcs.get("high_business_logic_correlations", 0)
        blrs["medium_business_logic_indicators"] = blcs.get("medium_business_logic_correlations", 0)
        blrs["executive_relevant_indicators"] = blcs.get("executive_relevant_correlations", 0)
        blrs["unique_indicator_types"] = sorted((blcs.get("by_type", {}) or {}).keys())
        blrs["unique_indicator_type_count"] = len(blrs["unique_indicator_types"])
        blrs["highest_risk_indicator"] = (
            "Critical" if blrs["critical_business_logic_indicators"] else
            "High" if blrs["high_business_logic_indicators"] else
            "Medium" if blrs["medium_business_logic_indicators"] else "NONE"
        )
        blrs["by_context"] = {"file": blcs.get("total_business_logic_correlations", 0), "function": 0, "api_route": 0}
        payload["business_logic_risk_summary"] = blrs

    cms = payload.get("crypto_misuse_summary", {})
    sbrc = payload.get("secret_blast_radius_correlation_summary", {})
    aars = payload.get("api_abuse_risk_summary", {})
    sccs = payload.get("security_control_coverage_summary", {})
    
    payload["metadata"]["kev_status"] = kis.get(
        "summary_status",
        "NOT_AVAILABLE"
    )
    payload["metadata"]["kev_packages"] = kis.get(
        "kev_packages",
        0
    )
    payload["metadata"]["reachable_kev_packages"] = kis.get(
        "reachable_kev_packages",
        0
    )
    payload["metadata"]["known_ransomware_use_packages"] = kis.get(
        "known_ransomware_use_packages",
        0
    )

    payload["metadata"]["vulnerable_packages_with_age"] = vas.get(
        "known_age_packages", 0
    )
    payload["metadata"]["kev_packages"] = vas.get("kev_packages", 0)
    payload["metadata"]["reachable_kev_packages"] = vas.get(
        "reachable_kev_packages", 0
    )
    payload["metadata"]["legacy_high_risk_packages"] = vas.get(
        "legacy_high_risk_packages", 0
    )
    
    payload["metadata"]["exposure_surface_status"] = ess.get(
    "executive_status",
    "NOT_AVAILABLE"
    )

    payload["metadata"]["supply_chain_trust_status"] = scts.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["supply_chain_trust_indicators"] = scts.get(
        "total_supply_chain_trust_indicators",
        0
    )

    payload["metadata"]["supply_chain_unpinned_dependencies"] = scts.get(
        "unpinned_dependencies",
        0
    )

    payload["metadata"]["supply_chain_git_dependencies"] = scts.get(
        "git_dependencies",
        0
    )

    payload["metadata"]["supply_chain_recent_packages"] = scts.get(
        "recent_packages",
        0
    )

    payload["metadata"]["supply_chain_unique_affected_component_risks"] = scts.get(
        "unique_affected_component_risks",
        0
    )
    payload["metadata"]["supply_chain_unique_high_component_risks"] = scts.get(
        "unique_high_component_risks",
        0
    )
    payload["metadata"]["supply_chain_unique_critical_component_risks"] = scts.get(
        "unique_critical_component_risks",
        0
    )


    payload["metadata"]["runtime_artifact_integrity_status"] = rais.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["runtime_artifact_integrity_indicators"] = rais.get(
        "total_artifact_integrity_indicators",
        0
    )

    payload["metadata"]["runtime_artifact_presence_indicators"] = rais.get(
        "total_artifact_presence_indicators",
        0
    )

    payload["metadata"]["runtime_artifact_unsigned"] = rais.get(
        "unsigned_artifacts",
        0
    )

    payload["metadata"]["runtime_artifact_tampered"] = rais.get(
        "tampered_artifacts",
        0
    )

    payload["metadata"]["runtime_artifact_packed"] = rais.get(
        "packed_binaries",
        0
    )

    payload["metadata"]["runtime_artifact_embedded_secrets"] = rais.get(
        "embedded_secret_artifacts",
        0
    )

    payload["metadata"]["runtime_artifact_provenance_gaps"] = rais.get(
        "provenance_gaps",
        0
    )

    payload["metadata"]["runtime_artifact_digest_pinning_gaps"] = rais.get(
        "digest_pinning_gaps",
        0
    )

    payload["metadata"]["runtime_artifact_checksum_gaps"] = rais.get(
        "checksum_gaps",
        0
    )

    payload["metadata"]["runtime_artifact_sbom_gaps"] = rais.get(
        "sbom_gaps",
        0
    )

    payload["metadata"]["runtime_artifact_global_integrity_indicators"] = rais.get(
        "global_artifact_integrity_indicators",
        0
    )

    payload["metadata"]["runtime_artifact_global_presence_indicators"] = rais.get(
        "global_artifact_presence_indicators",
        0
    )

    payload["metadata"]["runtime_artifact_executive_relevant_global"] = rais.get(
        "executive_relevant_global_indicators",
        0
    )
    
    payload["metadata"]["data_flow_sensitivity_status"] = dfss.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["data_flow_sensitivity_indicators"] = dfss.get(
        "total_data_flow_sensitivity_indicators",
        0
    )

    payload["metadata"]["data_flow_sensitivity_critical"] = dfss.get(
        "critical_indicators",
        0
    )

    payload["metadata"]["data_flow_sensitivity_high"] = dfss.get(
        "high_indicators",
        0
    )

    payload["metadata"]["data_flow_sensitivity_executive_relevant"] = dfss.get(
        "executive_relevant_indicators",
        0
    )


    payload["metadata"]["data_flow_correlation_status"] = dfcs.get(
        "correlation_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["data_flow_correlation_mode"] = dfcs.get(
        "correlation_mode",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["data_flow_correlated_flows"] = dfcs.get(
        "total_correlated_flows",
        0
    )

    payload["metadata"]["data_flow_critical_correlated_flows"] = dfcs.get(
        "critical_correlated_flows",
        0
    )

    payload["metadata"]["data_flow_high_correlated_flows"] = dfcs.get(
        "high_correlated_flows",
        0
    )

    payload["metadata"]["data_flow_file_context_flows"] = dfcs.get(
        "by_context",
        {}
    ).get("file_context", 0)

    payload["metadata"]["data_flow_function_context_flows"] = dfcs.get(
        "by_context",
        {}
    ).get("function_context", 0)


    payload["metadata"]["component_exposure_indicators"] = ess.get(
        "component_exposure_indicators",
        0
    )

    payload["metadata"]["global_exposure_indicators"] = ess.get(
        "global_exposure_indicators",
        0
    )

    payload["metadata"]["executive_relevant_global_exposure"] = ess.get(
        "confirmed_executive_global_indicators",
        0
    )
    
    
    
    payload["metadata"]["identity_access_risk_status"] = iars.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["identity_access_indicators"] = iars.get(
        "total_identity_access_indicators",
        0
    )

    payload["metadata"]["identity_access_critical"] = iars.get(
        "critical_identity_access_indicators",
        0
    )

    payload["metadata"]["identity_access_high"] = iars.get(
        "high_identity_access_indicators",
        0
    )

    payload["metadata"]["identity_access_executive_relevant"] = iars.get(
        "executive_relevant_indicators",
        0
    )

    payload["metadata"]["identity_access_correlation_status"] = iacs.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["identity_access_correlations"] = iacs.get(
        "total_identity_access_correlations",
        0
    )

    payload["metadata"]["identity_access_correlation_critical"] = iacs.get(
        "critical_identity_access_correlations",
        0
    )

    payload["metadata"]["identity_access_correlation_high"] = iacs.get(
        "high_identity_access_correlations",
        0
    )

    payload["metadata"]["identity_access_privileged_routes"] = iacs.get(
        "privileged_routes_observed",
        0
    )

    payload["metadata"]["identity_access_unauth_privileged_routes"] = iacs.get(
        "unauthenticated_privileged_routes",
        0
    )

    payload["metadata"]["auth_hardening_status"] = ahrs.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["auth_hardening_indicators"] = ahrs.get(
        "total_auth_hardening_indicators",
        0
    )

    payload["metadata"]["auth_hardening_critical"] = ahrs.get(
        "critical_auth_hardening_indicators",
        0
    )

    payload["metadata"]["auth_hardening_high"] = ahrs.get(
        "high_auth_hardening_indicators",
        0
    )

    payload["metadata"]["auth_hardening_executive_relevant"] = ahrs.get(
        "executive_relevant_indicators",
        0
    )
    
    
    payload["metadata"]["ai_model_risk_status"] = amrs.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["ai_model_risk_indicators"] = amrs.get(
        "total_ai_model_risk_indicators",
        0
    )

    payload["metadata"]["ai_model_risk_critical"] = amrs.get(
        "critical_ai_model_risk_indicators",
        0
    )

    payload["metadata"]["ai_model_risk_high"] = amrs.get(
        "high_ai_model_risk_indicators",
        0
    )

    payload["metadata"]["ai_model_risk_executive_relevant"] = amrs.get(
        "executive_relevant_indicators",
        0
    )

    payload["metadata"]["ai_model_risk_confirmed_executive"] = amrs.get(
        "confirmed_executive_risk_indicators",
        0
    )
    payload["metadata"]["ai_model_risk_executive_status"] = amrs.get(
        "executive_risk_status",
        "NO_CONFIRMED_EXECUTIVE_AI_RISK"
    )
    
    
    payload["metadata"]["business_logic_risk_status"] = blrs.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["business_logic_risk_indicators"] = blrs.get(
        "total_business_logic_indicators",
        0
    )

    payload["metadata"]["business_logic_risk_critical"] = blrs.get(
        "critical_business_logic_indicators",
        0
    )

    payload["metadata"]["business_logic_risk_high"] = blrs.get(
        "high_business_logic_indicators",
        0
    )

    payload["metadata"]["business_logic_risk_executive_relevant"] = blrs.get(
        "executive_relevant_indicators",
        0
    )

    payload["metadata"]["business_logic_file_context"] = blrs.get(
        "by_context",
        {}
    ).get("file", 0)

    payload["metadata"]["business_logic_function_context"] = blrs.get(
        "by_context",
        {}
    ).get("function", 0)

    payload["metadata"]["business_logic_api_route_context"] = blrs.get(
        "by_context",
        {}
    ).get("api_route", 0)
    
    
    
    payload["metadata"]["business_logic_correlation_status"] = blcs.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["business_logic_correlations"] = blcs.get(
        "total_business_logic_correlations",
        0
    )

    payload["metadata"]["business_logic_correlation_critical"] = blcs.get(
        "critical_business_logic_correlations",
        0
    )

    payload["metadata"]["business_logic_correlation_high"] = blcs.get(
        "high_business_logic_correlations",
        0
    )

    payload["metadata"]["business_logic_correlation_executive_relevant"] = blcs.get(
        "executive_relevant_correlations",
        0
    )
    
    
    payload["metadata"]["api_abuse_risk_status"] = aars.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["api_abuse_risk_indicators"] = aars.get(
        "total_api_abuse_indicators",
        0
    )

    payload["metadata"]["api_abuse_risk_critical"] = aars.get(
        "critical_api_abuse_indicators",
        0
    )

    payload["metadata"]["api_abuse_risk_high"] = aars.get(
        "high_api_abuse_indicators",
        0
    )

    payload["metadata"]["api_abuse_risk_unique"] = aars.get(
        "total_unique_api_abuse_indicators",
        0
    )

    payload["metadata"]["api_abuse_risk_executive_relevant"] = aars.get(
        "executive_relevant_indicators",
        0
    )

    payload["metadata"]["api_abuse_route_context"] = aars.get(
        "by_context",
        {}
    ).get("api_route_context", 0)
    
    
    payload["metadata"]["security_control_coverage_status"] = sccs.get(
        "defense_in_depth_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["security_control_coverage_grade"] = sccs.get(
        "coverage_grade",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["security_control_coverage_ratio"] = sccs.get(
        "coverage_ratio",
        0
    )

    payload["metadata"]["security_control_coverage_ratio_semantics"] = sccs.get(
        "coverage_ratio_semantics",
        "STATIC_EVIDENCE_ONLY_NOT_CONTROL_EFFECTIVENESS"
    )
    payload["metadata"]["security_control_domains_evaluated"] = sccs.get(
        "domains_evaluated",
        sccs.get("total_domains_evaluated", 0)
    )
    payload["metadata"]["security_control_domain_coverage_ratio"] = sccs.get(
        "domain_coverage_ratio",
        sccs.get("coverage_ratio", 0)
    )
    payload["metadata"]["security_control_total_rules_evaluated"] = sccs.get(
        "total_controls_evaluated",
        0
    )
    payload["metadata"]["security_control_rules_observed"] = sccs.get(
        "controls_observed",
        0
    )
    payload["metadata"]["security_control_rules_not_observed"] = sccs.get(
        "controls_not_observed",
        0
    )
    payload["metadata"]["security_control_rule_coverage_ratio"] = sccs.get(
        "control_coverage_ratio",
        0
    )

    payload["metadata"]["security_controls_observed"] = sccs.get(
        "controls_observed",
        0
    )

    payload["metadata"]["security_controls_not_observed"] = sccs.get(
        "controls_not_observed",
        0
    )

    payload["metadata"]["security_control_domains_observed"] = sccs.get(
        "domains_observed_count",
        0
    )

    payload["metadata"]["security_control_domains_not_observed"] = sccs.get(
        "domains_not_observed_count",
        0
    )

    payload["metadata"]["security_control_executive_relevant_gaps"] = sccs.get(
        "executive_relevant_gaps",
        0
    )
    
    
    
    payload["metadata"]["crypto_misuse_status"] = cms.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["crypto_misuse_indicators"] = cms.get(
        "total_crypto_misuse_indicators",
        0
    )

    payload["metadata"]["crypto_misuse_critical"] = cms.get(
        "critical_crypto_misuse_indicators",
        0
    )

    payload["metadata"]["crypto_misuse_high"] = cms.get(
        "high_crypto_misuse_indicators",
        0
    )

    payload["metadata"]["crypto_misuse_executive_relevant"] = cms.get(
        "executive_relevant_indicators",
        0
    )

    payload["metadata"]["crypto_misuse_executive_status"] = cms.get(
        "executive_risk_status",
        "NO_CONFIRMED_EXECUTIVE_CRYPTO_RISK"
    )
    
    
    
    
    

    payload["metadata"]["vulnerability_age_status"] = vas.get(
        "summary_status",
        "NOT_AVAILABLE"
    )
    
    payload["metadata"]["epss_status"] = eis.get(
    "summary_status",
    "NOT_AVAILABLE"
    )
    payload["metadata"]["known_epss_packages"] = eis.get(
        "known_epss_packages",
        0
    )
    payload["metadata"]["very_high_epss_packages"] = eis.get(
        "very_high_exploit_probability",
        0
    )
    payload["metadata"]["p0_immediate_packages"] = eis.get(
        "p0_immediate_packages",
        0
    )

    payload["metadata"]["exploitability_status"] = exs.get(
    "summary_status",
    "NOT_AVAILABLE"
    )
    payload["metadata"]["immediate_remediate_packages"] = exs.get(
        "immediate_remediate",
        0
    )
    payload["metadata"]["priority_patch_packages"] = exs.get(
        "priority_patch",
        0
    )
    
    payload["metadata"]["license_policy_status"] = lps.get(
    "summary_status",
    "NOT_AVAILABLE"
    )
    payload["metadata"]["license_notice_required_components"] = lps.get(
        "notice_required_components",
        0
    )

    payload["metadata"]["license_legal_review_required"] = lps.get(
        "legal_review_required_components",
        0
    )
    payload["metadata"]["license_unknown_components"] = lps.get(
        "unknown_license_components",
        0
    )
    payload["metadata"]["license_notice_required_components"] = lps.get(
        "notice_required_components",
        0
    )


    payload["metadata"]["vulnerable_packages"] = rv.get("vulnerable_packages", 0)
    payload["metadata"]["reachable_vulnerable_packages"] = rv.get(
        "reachable_vulnerable_packages", 0
    )
    payload["metadata"]["not_observed_vulnerable_packages"] = rv.get(
        "not_observed_vulnerable_packages", 0
    )
    payload["metadata"]["unknown_reachability_vulnerable_packages"] = rv.get(
        "unknown_reachability_vulnerable_packages", 0
    )

    payload["metadata"]["governance_signals_total"] = gss.get("total_signals", 0)
    payload["metadata"]["governance_high_signals"] = gss.get("high_signals", 0)
    payload["metadata"]["governance_medium_signals"] = gss.get("medium_signals", 0)
    payload["metadata"]["executive_decision"] = ed.get("executive_decision", "UNKNOWN")
    payload["metadata"]["executive_decision_priority"] = ed.get(
        "decision_priority", "UNKNOWN"
    )
    
    
    payload["metadata"]["release_readiness_decision"] = rrs.get(
        "release_decision",
        "UNKNOWN"
    )

    payload["metadata"]["release_readiness_priority"] = rrs.get(
        "release_priority",
        "UNKNOWN"
    )

    payload["metadata"]["release_readiness_confidence"] = rrs.get(
        "release_confidence",
        0
    )

    payload["metadata"]["release_readiness_blocking_gates"] = rrs.get(
        "blocking_gate_count",
        0
    )

    payload["metadata"]["release_readiness_review_gates"] = rrs.get(
        "review_gate_count",
        0
    )

    payload["metadata"]["release_readiness_status"] = rrs.get(
        "summary_status",
        "NOT_AVAILABLE"
    )
    
    payload["metadata"]["executive_decision_confidence"] = ed.get(
        "decision_confidence", 0
    )
    
    fms = payload.get("framework_mapping_summary", {})

    payload["metadata"]["framework_mapped_findings"] = fms.get("mapped_findings", 0)
    payload["metadata"]["framework_mapping_status"] = fms.get(
        "mapping_status",
        "NOT_AVAILABLE"
    )

    # --------------------------------------------------
    # Console Visibility
    # --------------------------------------------------
    
    _safe_print(
        "       => KEV Intelligence: "
        f"{kis.get('kev_packages', 0)} KEV | "
        f"{kis.get('reachable_kev_packages', 0)} reachable KEV | "
        f"{kis.get('known_ransomware_use_packages', 0)} ransomware-linked"
    )

    _safe_print(
        "       => Reachability Vulnerability Priority: "
        f"{rv.get('reachable_vulnerable_packages', 0)} reachable vulnerable | "
        f"{rv.get('not_observed_vulnerable_packages', 0)} not observed vulnerable | "
        f"{rv.get('unknown_reachability_vulnerable_packages', 0)} unknown"
    )


    _safe_print(
        "       => Vulnerability Age Intelligence: "
        f"{vas.get('kev_packages', 0)} KEV | "
        f"{vas.get('reachable_kev_packages', 0)} reachable KEV | "
        f"{vas.get('legacy_high_risk_packages', 0)} legacy high risk"
    )
    
    
    _safe_print(
        "       => Legacy Protocol Intelligence: "
        f"{lgs.get('component_legacy_indicators', 0)} component indicators | "
        f"{lgs.get('global_legacy_indicators', 0)} global indicators | "
        f"{lgs.get('executive_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => Exposure Surface Intelligence: "
        f"{ess.get('component_exposure_indicators', 0)} component indicators | "
        f"{ess.get('global_exposure_indicators', 0)} global indicators | "
        f"{ess.get('executive_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => EPSS Intelligence: "
        f"{eis.get('known_epss_packages', 0)} known EPSS | "
        f"{eis.get('very_high_exploit_probability', 0)} very high | "
        f"{eis.get('p0_immediate_packages', 0)} P0 immediate"
    )
    
    _safe_print(
        "       => Exploitability Decision: "
        f"{exs.get('immediate_remediate', 0)} immediate | "
        f"{exs.get('priority_patch', 0)} priority patch | "
        f"{exs.get('summary_status', 'NOT_AVAILABLE')}"
    )
    
    _safe_print(
          "       => SBOM License Policy: "
        f"{lps.get('legal_review_required_components', 0)} legal review | "
        f"{lps.get('unknown_license_components', 0)} unknown | "
        f"{lps.get('notice_required_components', 0)} notice required"
    )
    
    _safe_print(
         "       => Source/IP Compliance Scan: "
        f"{cips.get('copyright_ip_findings', 0)} findings | "
        f"{cips.get('critical', 0)} critical | "
        f"{cips.get('high', 0)} high | "
        f"{cips.get('decision', 'NO_COPYRIGHT_SIGNAL')}"
    )



    _safe_print(
        "       => Supply Chain Trust Intelligence: "
        f"{scts.get('total_supply_chain_trust_indicators', 0)} indicators | "
        f"{scts.get('high_affected_components', 0)} high affected | "
        f"{scts.get('summary_status', 'NOT_AVAILABLE')}"
    )


    _safe_print(
        "       => Runtime Artifact Integrity: "
        f"{rais.get('total_artifact_integrity_indicators', 0)} component integrity | "
        f"{rais.get('total_artifact_presence_indicators', 0)} component presence | "
        f"{rais.get('global_artifact_integrity_indicators', 0)} global integrity | "
        f"{rais.get('global_artifact_presence_indicators', 0)} global presence | "
        f"{rais.get('summary_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => Data Flow Sensitivity: "
        f"{dfss.get('total_data_flow_sensitivity_indicators', 0)} indicators | "
        f"{dfss.get('executive_relevant_indicators', 0)} executive relevant | "
        f"{dfss.get('summary_status', 'NOT_AVAILABLE')}"
    )

    dfc_context = dfcs.get("by_context", {})

    _safe_print(
        "       => Data Flow Correlation: "
        f"{dfcs.get('total_correlated_flows', 0)} correlated | "
        f"{dfcs.get('critical_correlated_flows', 0)} critical | "
        f"{dfcs.get('high_correlated_flows', 0)} high | "
        f"file {dfc_context.get('file_context', 0)} | "
        f"function {dfc_context.get('function_context', 0)} | "
        f"confirmed {dfcs.get('confirmed_flows', 0)} | "
        f"fallback_candidates {dfcs.get('fallback_candidate_flows', 0)} | "
        f"{dfcs.get('correlation_confidence', 'NOT_AVAILABLE')} | "
        f"{dfcs.get('correlation_mode', 'NOT_AVAILABLE')}"
    )
    
    
    _safe_print(
        "       => Identity Access Risk: "
        f"{iars.get('total_identity_access_indicators', 0)} indicators | "
        f"{iars.get('critical_identity_access_indicators', 0)} critical | "
        f"{iars.get('high_identity_access_indicators', 0)} high | "
        f"{iars.get('summary_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => Identity Access Correlation: "
        f"{iacs.get('total_identity_access_correlations', 0)} correlations | "
        f"{iacs.get('critical_identity_access_correlations', 0)} critical | "
        f"{iacs.get('high_identity_access_correlations', 0)} high | "
        f"privileged_routes {iacs.get('privileged_routes_observed', 0)} | "
        f"unauth_privileged {iacs.get('unauthenticated_privileged_routes', 0)} | "
        f"{iacs.get('summary_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => Auth Hardening Risk: "
        f"{ahrs.get('total_auth_hardening_indicators', 0)} indicators | "
        f"{ahrs.get('critical_auth_hardening_indicators', 0)} critical | "
        f"{ahrs.get('high_auth_hardening_indicators', 0)} high | "
        f"{ahrs.get('summary_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => Auth Hardening Correlation: "
        f"{ahcs.get('total_auth_hardening_correlations', 0)} correlations | "
        f"{ahcs.get('critical_auth_hardening_correlations', 0)} critical | "
        f"{ahcs.get('high_auth_hardening_correlations', 0)} high | "
        f"{ahcs.get('summary_status', 'NOT_AVAILABLE')}"
    )

    payload["metadata"]["auth_hardening_correlation_status"] = ahcs.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["auth_hardening_correlations"] = ahcs.get(
        "total_auth_hardening_correlations",
        0
    )

    payload["metadata"]["auth_hardening_correlation_critical"] = ahcs.get(
        "critical_auth_hardening_correlations",
        0
    )

    payload["metadata"]["auth_hardening_correlation_high"] = ahcs.get(
        "high_auth_hardening_correlations",
        0
    )

    payload["metadata"]["auth_hardening_correlation_executive_relevant"] = ahcs.get(
        "executive_relevant_correlations",
        0
    )


    _safe_print(
        "       => AI Model Risk: "
        f"{amrs.get('total_ai_model_risk_indicators', 0)} indicators | "
        f"{amrs.get('critical_ai_model_risk_indicators', 0)} critical | "
        f"{amrs.get('high_ai_model_risk_indicators', 0)} high | "
        f"{amrs.get('summary_status', 'NOT_AVAILABLE')}"
    )



    bl_context = blrs.get("by_context", {})

    _safe_print(
        "       => Business Logic Risk: "
        f"{blrs.get('total_business_logic_indicators', 0)} indicators | "
        f"{blrs.get('critical_business_logic_indicators', 0)} critical | "
        f"{blrs.get('high_business_logic_indicators', 0)} high | "
        f"file {bl_context.get('file', 0)} | "
        f"function {bl_context.get('function', 0)} | "
        f"{blrs.get('summary_status', 'NOT_AVAILABLE')}"
    )


    _safe_print(
        "       => Business Logic Correlation: "
        f"{blcs.get('total_business_logic_correlations', 0)} correlations | "
        f"{blcs.get('critical_business_logic_correlations', 0)} critical | "
        f"{blcs.get('high_business_logic_correlations', 0)} high | "
        f"{blcs.get('summary_status', 'NOT_AVAILABLE')}"
    )

    api_context = aars.get("by_context", {})

    _safe_print(
        "       => API Abuse Risk: "
        f"{aars.get('total_api_abuse_indicators', 0)} indicators | "
        f"{aars.get('total_unique_api_abuse_indicators', 0)} unique | "
        f"{aars.get('critical_api_abuse_indicators', 0)} critical | "
        f"{aars.get('high_api_abuse_indicators', 0)} high | "
        f"api {api_context.get('api_route_context', 0)} | "
        f"{aars.get('summary_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => Security Control Coverage: "
        f"{sccs.get('coverage_grade', 'NOT_AVAILABLE')} | "
        f"{sccs.get('coverage_ratio', 0)} coverage | "
        f"{sccs.get('domains_observed_count', 0)} domains observed | "
        f"{sccs.get('domains_not_observed_count', 0)} gaps | "
        f"{sccs.get('defense_in_depth_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => Crypto Misuse: "
        f"{cms.get('total_crypto_misuse_indicators', 0)} indicators | "
        f"{cms.get('critical_crypto_misuse_indicators', 0)} critical | "
        f"{cms.get('high_crypto_misuse_indicators', 0)} high | "
        f"{cms.get('summary_status', 'NOT_AVAILABLE')}"
    )


    _safe_print(
        "       => Secret Intelligence: "
        f"{sis.get('total_secrets', 0)} secrets classified | "
        f"{sis.get('critical_blast_radius', 0)} critical blast radius | "
        f"{sis.get('high_blast_radius', 0)} high blast radius | "
        f"{sis.get('validation_status', 'OFFLINE_ONLY_NOT_VALIDATED')}"
    )
    
    
    _safe_print(
        "       => Secret Blast Radius Correlation: "
        f"{sbrc.get('total_secret_blast_radius_correlations', 0)} correlations | "
        f"{sbrc.get('total_unique_secret_blast_radius', 0)} unique | "
        f"{sbrc.get('critical_unique_secret_blast_radius', 0)} critical unique | "
        f"{sbrc.get('correlation_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => Framework Enrichment: "
        f"{fms.get('mapped_findings', 0)} findings mapped | "
        f"{fms.get('mapping_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => Reachability-Aware Reporting: "
        f"{len(reachable_vulnerable_packages)} reachable vulnerable listed | "
        f"{len(not_observed_vulnerable_packages)} not observed vulnerable listed"
    )

    _safe_print(
        "       => Governance Signals: "
        f"{gss.get('total_signals', 0)} total | "
        f"{gss.get('high_signals', 0)} high | "
        f"{gss.get('medium_signals', 0)} medium"
    )
    
    _safe_print(
        "       => Release Readiness: "
        f"{rrs.get('release_decision', 'UNKNOWN')} | "
        f"{rrs.get('release_priority', 'UNKNOWN')} | "
        f"{rrs.get('blocking_gate_count', 0)} blocking gates | "
        f"{rrs.get('review_gate_count', 0)} review gates | "
        f"confidence {rrs.get('release_confidence', 0)}"
    )


    _safe_print(
        "       => Executive Decision: "
        f"{ed.get('executive_decision', 'UNKNOWN')} | "
        f"{ed.get('decision_priority', 'UNKNOWN')} | "
        f"confidence {ed.get('decision_confidence', 0)}"
    )

    meta = payload["metadata"]

    # Enterprise report truth: severity distribution must represent BOTH SAST
    # findings and unique vulnerable dependency packages.  SCA is deduplicated
    # at package/version level, while advisory_count remains available separately.
    dist = {sev: 0 for sev in ("Critical", "High", "Medium", "Low", "Info")}
    for finding in payload.get("findings", []) or []:
        sev = str(finding.get("severity") or "Info").title()
        if sev not in dist:
            sev = "Info"
        dist[sev] += 1
    for pkg in payload.get("sbom", []) or []:
        is_vulnerable = bool(pkg.get("vulnerabilities") or pkg.get("cve") or pkg.get("advisory_id"))
        if not is_vulnerable:
            continue
        sev = str(pkg.get("severity") or pkg.get("highest_vulnerability_severity") or "Unknown").title()
        if sev not in dist:
            # Unknown SCA severity is intentionally not forced into Low/Info.
            # Preserve a transparent total via metadata while the display buckets
            # remain severity-only.
            continue
        dist[sev] += 1
    meta["severity_distribution"] = dist
    meta["severity_distribution_scope"] = "SAST_findings_plus_unique_vulnerable_dependency_packages"
    meta["severity_distribution_sast"] = {sev: sum(1 for f in payload.get("findings", []) if str(f.get("severity") or "Info").title() == sev) for sev in dist}
    meta["severity_distribution_sca"] = {sev: sum(1 for p in payload.get("sbom", []) if (p.get("vulnerabilities") or p.get("cve") or p.get("advisory_id")) and str(p.get("severity") or p.get("highest_vulnerability_severity") or "Unknown").title() == sev) for sev in dist}
    meta["severity_distribution_sca_unknown"] = sum(
        1 for p in payload.get("sbom", [])
        if (p.get("vulnerabilities") or p.get("cve") or p.get("advisory_id"))
        and str(p.get("severity") or p.get("highest_vulnerability_severity") or "Unknown").title() == "Unknown"
    )
    meta["severity_distribution_unknown"] = meta["severity_distribution_sca_unknown"]

    # One canonical release decision for every output renderer.
    canonical_release = (payload.get("release_readiness", {}) or {}).get("release_decision") or meta.get("release_readiness_decision") or (payload.get("executive_decision", {}) or {}).get("executive_decision") or meta.get("executive_decision") or "UNKNOWN"
    meta["canonical_release_decision"] = canonical_release
    risk = meta["risk_score"]
    total = meta["total_findings"]
    paths = len(payload.get("attack_paths", []))

    _safe_print(
        f"       => {total} unique findings | Risk: {risk}/100 | Attack Paths: {paths}"
    )

    _print_dist(dist)

    # Optional benchmark enrichment: Juice Shop challenge declarations are
    # ground-truth metadata only; they never suppress or downgrade findings.
    _step("Final benchmark metadata enrichment")
    payload = enrich_juice_shop_ground_truth(payload, target)

    _step("Final mapping normalization")
    payload = _apply_final_mapping_normalization(payload)

    # Absolute serialization-boundary integrity pass: no later stage may
    # leave stale occurrence counts, affected files, or evidence in JSON.
    _step("Final report integrity pass")
    payload = _final_report_integrity_pass(payload)
    payload = _canonicalize_dependency_artifacts(payload)

    _cleanup_report_noise(payload)

    # V17.9.19: final serialization-boundary contract. JSON becomes the
    # canonical report artifact; PDF/Excel/SARIF/VEX consume this same safe
    # payload, eliminating renderer-specific remediation/evidence divergence.
    _step("Final report safety pass")
    payload = _apply_final_report_safety(payload)

    _step("Writing JSON report")
    json_path = output_dir / "clean_report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    _safe_print(f"       => {json_path}")

    generated_files = ["clean_report.json"]

    if not args.no_pdf:
        _step("Git diff / change intelligence")
    payload = enrich_report_payload_with_change_intelligence(payload, target)

    _step("Changed-line security findings")
    payload = enrich_changed_line_findings(payload)

    _step("Change-impact analysis")
    payload = enrich_change_impact(payload)

    _step("Security change graph")
    payload = enrich_security_change_graph(payload)

    _step("Security test coverage")
    payload = enrich_security_test_coverage(payload, target)

    _step("PR security summary")
    payload = enrich_pr_security_summary(payload)

    _step("Security test generation")
    payload = generate_security_test_blueprints(payload)

    _step("Historical finding intelligence")
    payload = enrich_historical_finding_intelligence(payload)

    _step("Malicious package intelligence")
    payload = enrich_malicious_package_intelligence(payload)

    _step("Fix / patch intelligence")
    payload = enrich_fix_patch_intelligence(payload)

    _step("PR review integration")
    payload = enrich_pr_review_integration(payload)



    _step("Finding lifecycle intelligence")
    payload = enrich_report_payload_with_finding_lifecycle(payload)

    _step("Generating PDF report")
    try:
        from reporting.pdf_report import generate_pdf_report

        pdf_path = output_dir / "Security_Report.pdf"
        generate_pdf_report(payload, str(pdf_path))
        generated_files.append(pdf_path.name)
        _safe_print(f"       => {pdf_path}")

        try:
            from reporting.executive_pdf_report import generate_executive_pdf_report
            executive_pdf_path = output_dir / "Security_Executive_Report.pdf"
            generate_executive_pdf_report(payload, str(executive_pdf_path))
            generated_files.append(executive_pdf_path.name)
            _safe_print(f"       => {executive_pdf_path}")
        except Exception as exc:
            _safe_print(f"       => Executive PDF failed: {exc}")
    except Exception as exc:
        _safe_print(f"       => PDF failed: {exc}")

    if not args.no_excel:
        _step("Generating Excel reports")
        try:
            from reporting.excel_report import (
                generate_excel_report,
                generate_executive_excel_report,
                generate_technical_excel_report,
            )

            combined_xlsx = output_dir / "Security_Report.xlsx"
            executive_xlsx = output_dir / "Security_Executive_Report.xlsx"
            technical_xlsx = output_dir / "Security_Technical_Report.xlsx"

            generate_excel_report(payload, str(combined_xlsx))
            generated_files.append(combined_xlsx.name)
            _safe_print(f"       => {combined_xlsx}")

            generate_executive_excel_report(payload, str(executive_xlsx))
            generated_files.append(executive_xlsx.name)
            _safe_print(f"       => {executive_xlsx}")

            generate_technical_excel_report(payload, str(technical_xlsx))
            generated_files.append(technical_xlsx.name)
            _safe_print(f"       => {technical_xlsx}")

        except ImportError:
            # Backward compatibility for older excel_report.py builds.
            try:
                from reporting.excel_report import generate_excel_report

                combined_xlsx = output_dir / "Security_Report.xlsx"
                generate_excel_report(payload, str(combined_xlsx))
                generated_files.append(combined_xlsx.name)
                _safe_print(f"       => {combined_xlsx}")
                _safe_print(
                    "       => Executive/Technical XLS skipped: "
                    "update reporting\\excel_report.py to the latest reporting build"
                )
            except Exception as exc:
                _safe_print(f"       => Excel failed: {exc}")
        except Exception as exc:
            _safe_print(f"       => Excel failed: {exc}")

    _step("Generating SARIF report")
    try:
        from reporting.sarif_export import write_sarif_report

        sarif_path = output_dir / "Security_Report.sarif"
        write_sarif_report(payload, str(sarif_path))
        generated_files.append(sarif_path.name)
        _safe_print(f"       => {sarif_path}")
    except Exception as exc:
        _safe_print(f"       => SARIF failed: {exc}")

    _step("Generating VEX report")
    try:
        from reporting.vex_export import write_vex_report

        vex_path = output_dir / "Security_Report.vex.json"
        write_vex_report(payload, str(vex_path))
        generated_files.append(vex_path.name)
        _safe_print(f"       => {vex_path}")
    except Exception as exc:
        _safe_print(f"       => VEX failed: {exc}")

    _step("Generating CycloneDX report")
    try:
        from reporting.cyclonedx_export import write_cyclonedx_report

        cdx_path = output_dir / "Security_CycloneDX.json"
        write_cyclonedx_report(payload, str(cdx_path))
        generated_files.append(cdx_path.name)
        _safe_print(f"       => {cdx_path}")
    except Exception as exc:
        _safe_print(f"       => CycloneDX failed: {exc}")

    scan_timing = _finish_scan_timing()
    payload.setdefault("metadata", {})["scan_timing"] = scan_timing

    # _finish_scan_timing runs after all renderer phases. Persist the final
    # authoritative timing object back into the canonical JSON artifact.
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
        _safe_print(f"       => scan_timing persisted to {json_path}")
    except Exception as exc:
        _safe_print(f"       => scan_timing persistence failed: {exc}")

    total_time = scan_timing["total_seconds"]
    _safe_print(f"\n  [DONE]  Scan complete in {total_time:.1f}s\n")
    _safe_print("  Output files:")

    for fname in generated_files:
        p = output_dir / fname
        if p.exists():
            _safe_print(f"       {fname:<35} ({p.stat().st_size / 1024:.1f} KB)")

    _safe_print("\n  INTELLIGENCE INSIGHTS:")
    for ins in payload.get("insights", []):
        _safe_print(f"    * {ins}")
    _safe_print("")


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()








