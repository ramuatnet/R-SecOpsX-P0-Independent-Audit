r"""
main.py  -  R-SecOpsX SAST v2.0  (branding: edit core/config.py)
"""
from __future__ import annotations
from datetime import datetime

import argparse
import json
import logging
import multiprocessing
from logging.handlers import RotatingFileHandler
import os
import re
import sys
import time
import zipfile
import threading
from pathlib import Path

from core.config import TOOL_NAME, TOOL_FULL
from core.path_utils import file_name, to_report_path

# Artifacts whose generation FAILED, as (artifact, reason).
#
# Exporter errors are caught individually so one broken format cannot destroy the
# other artifacts -- that fail-open behaviour is correct. But it also meant a lost
# artifact was invisible: BenchmarkJava-master shipped every format except both
# PDFs because reportlab raised LayoutError, main.py printed one line, and the run
# exited 0. Nothing on disk or in the exit code said a PDF was missing. This
# accumulator makes the loss explicit at the end of the run instead.
_REPORT_EXPORT_FAILURES: list[tuple[str, str]] = []
from core.finding_model import normalize_payload, build_rule_telemetry
from scanner.abom import generate_abom
from scanner.aibom import generate_aibom
from scanner.aibom_abom_correlation import correlate as correlate_aibom_abom
from scanner.apibom import generate_apibom
from scanner.cbom import generate_cbom
from scanner.iac_kubernetes import scan_kubernetes
from scanner.iac_terraform import scan_terraform
from scanner.mlbom import generate_mlbom
from scanner.iac_docker import scan_docker
from scanner.compliance_mapper import enrich_compliance, compliance_summary, compliance_summary_detail
from scanner.package_intelligence import enrich_report_payload, license_risk_count
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
from analysis.intelligence_provenance import (
    NOT_AVAILABLE,
    STATIC_REFERENCE,
    intelligence_note,
)
from analysis.live_intel_feeds import default_feed
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
    _safe_print("R-SecOpsX SCAN PERFORMANCE DATE/TIME + PHASE GAP")
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


# ---------------------------------------------------------------------------
# Console logging
# ---------------------------------------------------------------------------
# R-SecOpsX used to print through _safe_print() and nothing else: every message
# was unconditional, there was no way to raise or lower detail, and a failure
# inside a worker pool left no trace anywhere.  Phase 0 adopts the stdlib
# logging module so verbosity is a runtime choice and a durable record exists
# after the run (the file handler is added in main(), next to the reports).
#
# The console handler is attached at import time rather than inside main(),
# because _safe_print() is reachable before main() configures anything -- from
# module-level code and from the tests that import this module.  A logger with
# no handler would drop those messages entirely.
_LOG = logging.getLogger("rsx")
_LOG.propagate = False  # ours alone; root must not double-print it


class _ConsoleHandler(logging.Handler):
    """Write records to the *current* sys.stdout, ascii-safe.

    logging.StreamHandler captures its stream once, at construction time.
    That breaks under pytest's capture machinery -- capsys swaps sys.stdout
    after the handler already exists -- and under any late redirect, so the
    output would skip the capture and land on the real terminal.  Resolving
    the stream on every emit keeps both working, and keeps the ascii-replace
    fallback the original _safe_print() carried for consoles that cannot
    encode the text.
    """

    def emit(self, record):
        try:
            text = self.format(record)
            stream = sys.stdout
            try:
                stream.write(text + "\n")
            except UnicodeEncodeError:
                stream.write(text.encode("ascii", errors="replace").decode("ascii") + "\n")
            stream.flush()
        except Exception:  # a logger must never take the tool down
            self.handleError(record)


_CONSOLE_HANDLER = None


def _install_console_logging():
    global _CONSOLE_HANDLER
    if _CONSOLE_HANDLER is not None and _CONSOLE_HANDLER in _LOG.handlers:
        return
    handler = _ConsoleHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.setLevel(logging.INFO)  # clean until _setup_logging says otherwise
    _LOG.addHandler(handler)
    _CONSOLE_HANDLER = handler
    # The logger sits at DEBUG, not at the default verbosity.  The verbosity
    # is applied to the console handler instead, so a DEBUG record is always
    # *created* and is able to reach the durable scan.log even when the
    # operator has not asked to see it on screen.
    _LOG.setLevel(logging.DEBUG)


_install_console_logging()

# Verbosity rungs, named so the CLI, the security gate and the tests agree.
VERBOSITY_LEVELS = {
    "quiet": logging.WARNING,
    "info": logging.INFO,
    "verbose": logging.DEBUG,
    "debug": logging.DEBUG,
}


def _setup_logging(verbosity):
    """Apply the --quiet/--verbose/--debug choice.

    --verbose and --debug both sit at DEBUG, but they are not the same thing:
    --verbose shows this tool's own diagnostics, while --debug additionally
    opens the root logger so third-party ones (HTTP retries, PDF layout,
    advisory fetches) appear too, each timestamped so a line can be placed on
    the run's timeline.

    The level is applied to the *console handler*, never to the logger: the
    logger stays at DEBUG so every record exists and can reach scan.log, and
    only the screen is thinned by the operator's flag.
    """
    if _CONSOLE_HANDLER is not None:
        _CONSOLE_HANDLER.setLevel(VERBOSITY_LEVELS.get(verbosity, logging.INFO))
    if verbosity == "debug":
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
            stream=sys.stdout,
            force=True,
        )


# The run's durable record.  Held globally so a second main() in the same
# process (the tests import this module) can swap the handler instead of
# stacking another one and printing every record twice.
_SCAN_LOG_HANDLER = None


def _attach_scan_log(output_dir):
    """Give the run a complete record next to the other artefacts.

    The console is for the operator and moves with --quiet/--verbose/--debug.
    This file is for whoever reads the run afterwards, so it is written at
    DEBUG whatever the console is set to, and it is rotated rather than left
    to grow without bound -- a scanner that can run for hours must not fill a
    disk with its own log.
    """
    global _SCAN_LOG_HANDLER
    if _SCAN_LOG_HANDLER is not None:
        _LOG.removeHandler(_SCAN_LOG_HANDLER)
        try:
            _SCAN_LOG_HANDLER.close()
        except Exception:
            pass
        _SCAN_LOG_HANDLER = None
    try:
        path = Path(output_dir) / "scan.log"
        # Opened eagerly rather than delay=True.  A deferred handler only
        # fails on first emit, by which point the record is lost and the
        # operator has been told the log exists; opening here raises OSError
        # up front, so an unusable path is reported instead of silently
        # swallowing the whole run's diagnostics.
        handler = RotatingFileHandler(
            path, maxBytes=5 * 1024 * 1024, backupCount=3,
            encoding="utf-8",
        )
        handler.setLevel(logging.DEBUG)  # the operator's flags must not thin it
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
        _LOG.addHandler(handler)
        _SCAN_LOG_HANDLER = handler
        return path
    except OSError as exc:  # a missing log must not stop a scan
        _LOG.warning("       ! scan.log unavailable: %s", exc)
        return None


def _safe_print(text):
    _LOG.info(text)


def _safe_print_error(text):
    """For messages that must survive --quiet.

    Usage errors and export failures are the one thing a quiet console still
    has to show, so they ride a level above the progress traffic.
    """
    _LOG.error(text)


# ---------------------------------------------------------------------------
# Security gate
# ---------------------------------------------------------------------------
# The five severities the report itself uses.  core.analyzer's
# severity_distribution() and _print_dist() already agree on these, so the
# gate counts in the vocabulary the reader sees instead of inventing a second
# one alongside it.
_REPORT_SEVERITIES = ("critical", "high", "medium", "low", "info")

# Thresholds --fail-on can be set to.  A finding at the chosen rung *or above*
# fails the gate, so --fail-on high fails on Critical as well.
_GATE_RUNGS = ("critical", "high", "medium")

# How a dependency package declares itself vulnerable, and where its severity
# lives.  These mirror the predicate main.py already uses when it builds
# metadata.severity_distribution, whose scope string is
# "SAST_findings_plus_unique_vulnerable_dependency_packages".
def _is_vulnerable_package(pkg):
    return bool(pkg.get("vulnerabilities") or pkg.get("cve") or pkg.get("advisory_id"))


def _package_severity(pkg):
    return str(pkg.get("severity") or pkg.get("highest_vulnerability_severity")
               or "Unknown").title()


def _security_gate(findings, fail_on, sbom=None):
    """Read the scan and decide whether the --fail-on threshold is met.

    The population is the one the report itself describes: SAST findings
    *plus* vulnerable dependency packages, the same scope as
    metadata.severity_distribution.  Counting findings alone under-reports
    exactly the severities a gate exists to catch -- a clean SAST run with a
    Critical vulnerable dependency would otherwise report PASSED.

    With no threshold the gate is recorded as not requested and passes, so a
    plain run exits exactly as it did before the flag existed.  Severity is
    only ever *read* here -- no finding's own severity, risk score or
    remediation ranking is touched.
    """
    counts = {sev: 0 for sev in _REPORT_SEVERITIES}
    unrecognised = {}

    def _tally(raw, source=None):
        key = str(raw or "").strip().lower()
        if key in counts:
            counts[key] += 1
        else:
            # Tagged with its source so an unrecognisable package severity
            # cannot be mistaken for an unrecognisable finding severity.
            label = f"{source}:{key or '(blank)'}" if source else (key or "(blank)")
            unrecognised[label] = unrecognised.get(label, 0) + 1

    for f in findings or []:
        if isinstance(f, dict):
            _tally(f.get("severity"))
    for pkg in sbom or []:
        if isinstance(pkg, dict) and _is_vulnerable_package(pkg):
            # "Unknown" is deliberately not a rung -- the report's own table
            # skips it for the same reason.  It is reported here so an
            # unclassifiable package can never be read as "nothing at this
            # severity".
            _tally(_package_severity(pkg), "sca")

    rung = str(fail_on or "").strip().lower() or None
    if rung is not None and rung not in _GATE_RUNGS:
        raise ValueError(f"--fail-on must be one of {_GATE_RUNGS}, got {fail_on!r}")

    if rung is None:
        blocking = {}
    else:
        above = _REPORT_SEVERITIES[:_REPORT_SEVERITIES.index(rung) + 1]
        blocking = {sev: counts[sev] for sev in above if counts[sev]}

    return {
        "threshold": rung,                 # null when no gate was requested
        "security_gate_passed": not blocking,
        "blocking_counts": blocking,
        "total_blocking": sum(blocking.values()),
        "severity_counts": counts,
        # Never folded into the five above: an unseen spelling has to stay
        # visible rather than quietly counted as clean.
        "unrecognised_severities": unrecognised,
    }


def _record_security_gate(payload, fail_on):
    """Attach the gate to the payload's metadata and return it.

    It is written beside the other metadata rather than bolted on afterwards,
    and returned so the exit code can use the identical object -- the file and
    the caller must never report different answers about the same scan.
    """
    gate = _security_gate(payload.get("findings") or [], fail_on,
                          payload.get("sbom") or [])
    payload.setdefault("metadata", {})["security_gate"] = gate
    return gate


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

        _normalize_attack_path_paths(payload, target)


def _normalize_attack_path_paths(payload: dict, target: str) -> None:
    """Give attack paths the same path treatment findings already get.

    MEASURED DEFECT. Attack paths were built from the finding's PRE-normalisation
    `file`, and this function only ever walked `findings`. So on a real scan every
    attack path published a raw scanner-host absolute path while no finding did.
    Verified on prodtest AI Benchmarks babyagi-main: 8 of 8 attack paths carried

        D:\\Data\\Code test\\prodtest\\AI Benchmarks\\babyagi-main\\babyagi-main\\babyagi\\api\\__init__.py

    where every finding carried `babyagi/api/__init__.py`. Two problems in one
    string: the scanner host's absolute layout is disclosed (G-070, still open),
    and the project directory is DOUBLED because the corpus nests
    AI Benchmarks/<project>/<project>. The rendered narrative then read "Observed at
    D:\\...\\babyagi-main\\babyagi-main\\...", which is not a path a reader can open
    and is not the path the findings table shows for the same defect.

    The narrative embeds the path as prose, so normalising only the `file` field
    would leave the sentence quoting a path the record no longer holds -- the two
    would disagree inside one record. The narrative is rewritten to match, and only
    when the two actually differ.
    """
    for ap in payload.get("attack_paths") or []:
        if not isinstance(ap, dict):
            continue

        original = str(ap.get("file") or "")
        if not original:
            continue

        normalized = to_report_path(original, target)
        if normalized == original:
            continue

        narrative = str(ap.get("narrative") or "")
        if narrative and original in narrative:
            ap["narrative"] = narrative.replace(original, normalized)

        ap["file"] = normalized
        ap["file_name"] = file_name(normalized)

        for occ in ap.get("occurrences") or []:
            if isinstance(occ, dict) and occ.get("file"):
                occ["file"] = to_report_path(str(occ["file"]), target)
        
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
                    # The path token may live in the occurrence's own taint path
                    # rather than the snippet: `open(p)` carries no path word,
                    # while its taint path `request.GET.get('path') -> p -> open`
                    # does. Search the occurrence's own evidence, not the snippet
                    # alone; another occurrence's taint is still never consulted.
                    supported = bool(
                        "->" in taint
                        and re.search(r"(?:file|path|filename|dest|target|name)", low + "\n" + taint)
                    )
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
    # Report-wide absence marker.  Written in place of `no_fixed` when the
    # component carries no advisory at all: nothing was looked up, so stating
    # that the advisory dataset was searched and came back empty would assert a
    # search that never happened.  Both renderers already print '--' for a row
    # with no advisory, so this keeps the data and the page in agreement.
    not_applicable = '--'
    _re = __import__('re')

    def _has_advisory(record):
        """True only when the record names a vulnerability that could be fixed.

        Deliberately mirrors `_v17923_fixed_text()` in reporting/pdf_report.py
        and reporting/excel_report.py.  The producer and the two renderers must
        agree on which rows deserve the "no fixed version" sentence, or one
        layer re-introduces the prose the other one just removed.
        """
        return bool(
            record.get('cve') or record.get('advisory_id') or
            record.get('cve_list') or record.get('advisory_ids') or
            record.get('vulnerabilities') or
            record.get('vulnerability_intelligence')
        )

    def _is_prose(token):
        """A version token never contains a word; a sentence always does.

        Whitespace plus a three-letter word separates English from a version
        range: `2.0.0-beta` and `>= 1.2.3` are kept, while
        'No fixed version identified in current advisory dataset.' is not.
        """
        return bool(_re.search(r'\s', token) and _re.search(r'[A-Za-z]{3,}', token))

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
        # Placeholders standing for "nothing here" rather than naming a
        # version.  `--` matters most: it is what this function writes for an
        # advisory-less component, so letting it through would re-ingest the
        # marker as data and turn `fixed_versions` into `['--']` on the next
        # pass - a different value every run, never converging.
        absent = {'unknown', 'none', 'null', 'n/a', 'na', '--'}
        if text.lower() in absent:
            return
        for token in _re.split(r'[,;\r\n]+', text):
            token = token.strip()
            if not token or token.lower() in absent:
                continue
            # Prose is dropped rather than yielded.  Yielding it let a sentence
            # be split into fragments that were then joined back up and printed
            # as if they were versions - which is how 'No fixed version
            # identified ...' reached 165 Fixed In cells belonging to
            # components that have no advisory.  Dropping it also lets the
            # advisory check below choose the wording for each row.
            if not _is_prose(token):
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
            # Reached when a field was supplied but held nothing usable.  Only
            # a component with an advisory may be told that no fix was found;
            # for every other one there is no fix *to* find, so record the
            # absence rather than a lookup outcome.
            if _has_advisory(record):
                record['fixed_versions'] = [no_fixed]
                record['fixed_in'] = no_fixed
            else:
                record['fixed_versions'] = []
                record['fixed_in'] = not_applicable
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
            "cpe": pkg.get("cpe"),
            "primary_vulnerability_id": primary_id,
            "cve": pkg.get("cve"),
            "cve_list": cves,
            "advisory_id": pkg.get("advisory_id"),
            "advisory_ids": advisories,
            "cvss": pkg.get("cvss"),
            "cvss_score": pkg.get("cvss_score", pkg.get("cvss")),
            "cvss_version": pkg.get("cvss_version") or "UNKNOWN",
            "cvss_vector": pkg.get("cvss_vector"),
            "cvss_source": pkg.get("cvss_source") or "UNKNOWN",
            "cvss_preferred_score": pkg.get("cvss_preferred_score"),
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
            # G-003: this row is a JSON-only view with no renderer in front of
            # it, so the provenance must travel with the value itself.
            "kev_provenance": pkg.get("kev_provenance") or STATIC_REFERENCE,
            "epss_provenance": pkg.get("epss_provenance")
            or (STATIC_REFERENCE if pkg.get("epss_score") is not None
                else NOT_AVAILABLE),
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
    # The guard skips any *already-redacted* bracketed marker, not just ones
    # that literally start "[REDACTED": our own evidence builders emit
    # "[HIGH-ENTROPY VALUE REDACTED]", "[SECRET MATERIAL REDACTED]" etc., and
    # re-masking those turned "password=[HIGH-ENTROPY VALUE REDACTED]" into the
    # unbalanced "password=[REDACTED SECRET] VALUE REDACTED]".
    r"(?P<prefix>\b(?:password|passwd|secret|client[-_ ]secret|api[-_ ]?key|access[-_ ]?key|private[-_ ]?key|jwt[-_ ]?secret|token)\b\s*[:=]\s*)(?P<quote>['\"]?)(?!\[[^\[\]]*REDACTED)(?P<value>[^\s,'\";]+)(?P<endquote>['\"]?)",
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

def _refresh_supply_chain_insight(payload: dict) -> None:
    """Re-anchor the SUPPLY CHAIN insight to final reachability truth.

    generate_insights() derives that entry from the SBOM view available when
    build_report_payload() runs, so it does not carry the package-level
    reachability evidence assembled later. This rewrites only that one entry
    and leaves every other insight untouched.
    """
    if payload.get("insights") is None:
        return
    reachable_vuln = len(payload.get("reachable_vulnerable_packages") or [])
    updated_insights = []
    for insight in payload.get("insights") or []:
        if isinstance(insight, str) and insight.startswith("SUPPLY CHAIN:"):
            vuln_count = sum(
                1 for pkg in payload.get("sbom") or []
                if isinstance(pkg, dict) and _safe_float(pkg.get("cvss")) >= 7.0
            )
            insight = (
                f"SUPPLY CHAIN: {vuln_count} dependency packages with CVSS >= 7.0 detected. "
                f"{reachable_vuln} vulnerable dependency packages have statically observed "
                "reachability evidence. This does not by itself prove runtime execution. Upgrade affected packages to patched "
                "versions before release."
            )
        updated_insights.append(insight)
    payload["insights"] = updated_insights

def _rebuild_finding_derived_aggregates(payload: dict) -> dict:
    """Recompute finding-derived top-level aggregates at the serialization boundary.

    `_final_report_integrity_pass()` drops findings whose occurrences were all
    pruned by the evidence gate, and `_cleanup_report_noise()` can remove more.
    `owasp`, `mitre` and `insights` are each built exactly once inside
    build_report_payload() from the *pre-prune* population, so they silently
    drift from `findings[]` afterwards. Measured on the Juice Shop corpus:
    `metadata.total_findings` 1439 vs 1293 written, `owasp` summing to 1436
    against a 1290-entry `findings` array, and an insight block still claiming
    9 SSRF / 4 deserialization / 141 hardcoded-credential findings against
    final counts of 6 / 1 / 3.

    This pass is read-only with respect to findings: it never adds, removes,
    rewrites or re-scores a finding, it only refreshes the aggregates that
    describe them. Engine failure falls back to leaving the existing
    aggregates in place rather than dropping them.
    """
    findings = [f for f in (payload.get("findings") or []) if isinstance(f, dict)]
    try:
        from core.analyzer import _build_mitre_summary, _build_owasp_summary, generate_insights
        payload["owasp"] = _build_owasp_summary(findings)
        payload["mitre"] = _build_mitre_summary(findings)
        payload["insights"] = generate_insights(
            findings,
            [p for p in (payload.get("sbom") or []) if isinstance(p, dict)],
            payload.get("attack_paths") or [],
        )
    except Exception:
        return payload
    _refresh_supply_chain_insight(payload)
    return payload

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


def _create_security_report_archive(
    output_dir: Path,
    target_name: str,
    generated_files: list[str],
) -> Path | None:
    """
    Package generated security assessment artifacts into a ZIP archive.

    The archive is intentionally created outside output_dir so that it
    cannot recursively include itself or become part of a future report
    package.

    Example:
        GenAI-Red-Team-Lab-main Security_Report 03102026 2037.zip
    """
    try:
        output_dir = Path(output_dir)
        target_name = str(target_name).strip() or "Security_Report"

        timestamp = time.strftime("%d%m%Y %H%M")
        archive_name = f"{target_name} Security_Report {timestamp}.zip"
        archive_path = output_dir.parent / archive_name

        if archive_path.exists():
            archive_path.unlink()

        files_to_archive = []

        for filename in generated_files:
            source = Path(filename)

            if not source.is_absolute():
                source = output_dir / filename

            if source.is_file():
                files_to_archive.append(source)

        if not files_to_archive:
            _safe_print("       => Security report ZIP skipped: no generated files")
            return None

        with zipfile.ZipFile(
            archive_path,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:

            for source in files_to_archive:
                archive.write(
                    source,
                    arcname=source.name,
                )

        if not archive_path.exists() or archive_path.stat().st_size <= 0:
            raise RuntimeError(
                "Security report ZIP was not created or is empty"
            )

        _safe_print(
            f"       => Security report ZIP: {archive_path}"
        )

        return archive_path

    except Exception as exc:
        _safe_print(
            f"       => Security report ZIP failed: {exc}"
        )
        return None

def _apply_epss_kev_provenance_banner(payload: dict, kis: dict | None = None,
                                       eis: dict | None = None) -> dict:
    """G-003/G-001/G-002: stamp one authoritative, machine-readable honesty
    statement.

    A consumer reading ``epss_score`` or ``kev_status`` alone cannot tell
    whether the value came from the live FIRST.org / CISA feeds or from the
    seed tables compiled into the build, so the provenance is published once
    at the payload root where JSON, Excel and PDF consumers all look first.

    ``live_feeds_wired`` is **derived from the data**, never from configuration
    or from the mere presence of the feed module: it is True only when at least
    one value in this payload actually arrived from a feed.  A scan run with the
    feeds enabled but unreachable still reports False, because that is the
    truth about the numbers sitting above it.

    This only *labels*; it never mutates a score, bucket, priority, severity,
    reachability state or release decision.
    """
    kis = kis if kis is not None else (payload.get("kev_intelligence_summary") or {})
    eis = eis if eis is not None else (payload.get("epss_intelligence_summary") or {})

    epss_prov = eis.get("provenance") or STATIC_REFERENCE
    kev_prov = kis.get("provenance") or STATIC_REFERENCE
    live = bool(eis.get("live_feeds_used")) or bool(kis.get("live_feeds_used"))

    banner = {
        "epss": epss_prov,
        "kev": kev_prov,
        "live_feeds_wired": live,
        # Derived per payload, so it can never claim "not the live feed" about
        # a value that is live, nor the reverse.
        "note": intelligence_note(
            epss_prov,
            kev_prov,
            epss_as_of=eis.get("as_of"),
            kev_as_of=kis.get("catalog_version") or kis.get("as_of"),
        ),
        "epss_as_of": eis.get("as_of"),
        "kev_catalog_version": kis.get("catalog_version"),
        "kev_as_of": kis.get("as_of"),
        "sources": {
            "epss": eis.get("sources") or {},
            "kev": kis.get("sources") or {},
        },
    }
    payload.setdefault("metadata", {})["epss_kev_provenance"] = banner
    return banner


def _build_qbom_layers(payload):
    """Compute both QBOM documents and attach them to the payload.

    Returns {name: document_or_None, ...} for the report stage to write to disk.

    Called while the payload is still being assembled, NOT in the report stage.
    Both layers used to be computed just before the Excel export, which is after
    generate_pdf_report(), so the PDF's post-quantum section rendered "no
    assessment was produced" while clean_report.json for the same run carried a
    populated layer. Two artifacts from one scan disagreeing about whether the scan
    had an assessment is worse than either answer alone.

    Neither document is allowed to abort the scan. A QBOM that cannot be built is
    recorded as REVIEW_REQUIRED with its reason, because the alternative -- losing
    the whole report to one BOM type -- trades a disclosed gap for a silent one.
    """
    docs = {"certin": None, "pq": None}
    errors = {}

    # CERT-In v2.0 Table 8: the regulatory conformance projection.
    try:
        from core.qbom_mappings import build_qbom, qbom_reference

        doc = build_qbom(payload)
        docs["certin"] = doc
        payload["qbom"] = doc

        cov = doc["element_coverage"]
        payload["qbom_summary"] = {
            "status": "PARTIAL_BY_CONSTRUCTION",
            "artifact": "Security_QBOM.qbom.json",
            "bom_type": "QBOM (Quantum Bill of Materials)",
            "minimum_elements": cov["minimum_elements"],
            "observable_from_source": cov["observable_from_source"],
            "not_observable_from_source": cov["not_observable_from_source"],
            "not_observable_elements": cov["not_observable_elements"],
            "quantum_components_detected": doc["quantum_components_detected"],
            "quantum_components_found": len(doc["quantum_components"]),
            "post_quantum_references_found": len(doc["post_quantum_references"]),
            "scope": doc["scope"],
            "limits": doc["limits"],
            "hbom_implemented": False,
            "hbom_note": ("A Hardware Bill of Materials (Table 11) is a distinct "
                          "artifact and is NOT implemented. The Table 8 Hardware "
                          "element is correspondingly null."),
            **qbom_reference(),
        }
    except Exception as exc:  # noqa: BLE001 - deliberate: fail open, disclose
        errors["certin"] = f"{type(exc).__name__}: {exc}"[:300]
        payload["qbom_summary"] = {
            "status": "REVIEW_REQUIRED",
            "error": errors["certin"],
            "bom_type": "QBOM (Quantum Bill of Materials)",
        }

    # The PQ layer: post-quantum exposure of this project's cryptographic assets.
    # Separate from the CERT-In document because they answer different questions --
    # conformance versus migration order -- and are built from different inputs.
    try:
        from scanner.crypto_quantum_analyzer import (
            build_pqc_verdict_matrix,
            correlate_cbom_to_qbom,
            summarize_quantum_exposure,
        )

        assets = correlate_cbom_to_qbom(payload.get("cbom") or [])
        exposure = summarize_quantum_exposure(assets)
        doc = {
            "schema_version": "1.0",
            "bom_type": "PQ_QBOM",
            "layer": "post_quantum_crypto_exposure",
            "distinct_question": (
                "Which cryptographic assets in this source break under a "
                "cryptographically relevant quantum computer, and in what order "
                "should they be migrated? Distinct from the CERT-In Table 8 "
                "conformance document in Security_QBOM.qbom.json."
            ),
            "exposure_summary": exposure,
            "migration_queue": exposure["migration_queue"],
            "assets": assets,
            "classification_rules": {
                "QUANTUM_VULNERABLE": (
                    "Broken by Shor's algorithm. Applies to RSA, DSA, DH, ECDSA, "
                    "ECDH and the Edwards curves -- including ed25519, which is "
                    "vulnerable precisely BECAUSE it is strong."
                ),
                "QUANTUM_MARGIN_CRITICAL": (
                    "Grover destroys the margin outright rather than reducing it. "
                    "A 64-bit effective key such as DES or 3DES falls to roughly "
                    "32 bits, below any acceptable floor. Separate from "
                    "QUANTUM_VULNERABLE because the mechanism is not Shor's and "
                    "the migration advice differs: a 64-bit symmetric key must be "
                    "replaced by one of adequate length, not by a PQC algorithm."
                ),
                "PQC": (
                    "Already post-quantum: the ML-KEM, ML-DSA and SLH-DSA "
                    "families, including their NIST parameter sets."
                ),
                "QUANTUM_IMPACT_ASSESSED": (
                    "Reduced margin, not broken. Grover's algorithm halves the "
                    "effective key length, so AES-128 becomes AES-64 equivalent. "
                    "Not a migration trigger on its own."
                ),
                "UNKNOWN": (
                    "The primitive could not be classified. This is NOT a safe "
                    "result: it means the inventory cannot tell, and it is "
                    "reported as its own category rather than folded into a "
                    "low-risk bucket."
                ),
            },
            "source": ("Derived from this scan's own CBOM by "
                       "scanner/crypto_quantum_analyzer. No external database was "
                       "consulted."),
            "limits": (
                "Static source analysis. An asset absent from the CBOM is absent "
                "from this document too; absence here is not evidence of absence "
                "in the deployed system. Key sizes are reported only where the "
                "source states them, and are null otherwise."
            ),
        }
        # Phase 4.5: multi-jurisdiction PQC verdicts over the same
        # correlated assets. The matrix lives in the PQ document rather than
        # the CERT-In Table 8 document because jurisdiction policy is a
        # migration projection, and the CERT-In artifact models a fixed
        # element list (its conformance contract does not grow new keys).
        doc["pqc_policy_matrix"] = build_pqc_verdict_matrix(assets)
        docs["pq"] = doc
        payload["qbom_pq"] = doc
        payload["qbom_pq_summary"] = {
            "status": "MEASURED",
            "artifact": "Security_QBOM.pq.json",
            "bom_type": "PQ QBOM (post-quantum crypto exposure)",
            "total_usage_sites": exposure["total_usage_sites"],
            "distinct_assets": exposure["total_assets"],
            "classified": exposure["classified"],
            "unclassified": exposure["unclassified"],
            "by_quantum_status": exposure["by_quantum_status"],
            "migration_queue_length": len(exposure["migration_queue"]),
            "coverage_note": exposure["coverage_note"],
            "aggregation_note": exposure.get("aggregation_note"),
            "pqc_policy": {
                "jurisdictions": [
                    p["id"] for p in doc["pqc_policy_matrix"]["packs"]
                ],
                "verdict_totals": doc["pqc_policy_matrix"]["rollup"],
            },
        }
    except Exception as exc:  # noqa: BLE001 - deliberate: fail open, disclose
        errors["pq"] = f"{type(exc).__name__}: {exc}"[:300]
        payload["qbom_pq_summary"] = {
            "status": "REVIEW_REQUIRED",
            "error": errors["pq"],
            "bom_type": "PQ QBOM (post-quantum crypto exposure)",
        }

    docs["errors"] = errors
    return docs


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
    parser.add_argument(
        "--no-pdf", action="store_true",
        help="skip PDF rendering (Security_Report.pdf and "
             "Security_Executive_Report.pdf). clean_report.json, the SBOM, QBOM, "
             "SARIF, VEX and Excel workbooks are still written. This flag was "
             "declared but never consulted, so it skipped nothing until G-138.")
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
    _verbosity = parser.add_mutually_exclusive_group()
    _verbosity.add_argument(
        "--quiet", "-q", dest="verbosity", action="store_const", const="quiet",
        help="console shows only warnings and errors",
    )
    _verbosity.add_argument(
        "--verbose", dest="verbosity", action="store_const", const="verbose",
        help="add this tool's own debug diagnostics (third-party stays quiet)",
    )
    _verbosity.add_argument(
        "--debug", dest="verbosity", action="store_const", const="debug",
        help="add this tool's and third-party debug diagnostics, timestamped",
    )
    parser.add_argument(
        "--fail-on", dest="fail_on", choices=list(_GATE_RUNGS), default=None,
        help=(
            "exit 1 when the report holds a finding at or above this severity "
            "(--fail-on high fails on Critical too). Omitted, the tool exits 0 "
            "whatever it finds. This only decides the exit code -- no "
            "severity, risk score or ranking is changed by it."
        ),
    )
    parser.add_argument(
        "--sbom", dest="sbom", default=None,
        help=(
            "ingest an existing CycloneDX/SPDX JSON SBOM instead of scanning "
            "source: the document's components are normalised, advisory-"
            "enriched (OSV), CPE/licence-stamped and reported through the "
            "same pipeline. No SAST/secrets/IaC findings are produced (there "
            "is no source to scan)."
        ),
    )
    parser.add_argument(
        "--baseline", dest="baseline", default=None,
        help=(
            "compare the current inventory against a previous SBOM or "
            "clean_report.json: adds payload['baseline_diff'] with "
            "added/removed/changed components and vulnerability deltas. "
            "Report-only; it never changes the exit code."
        ),
    )
    parser.set_defaults(verbosity="info")
    args = parser.parse_args()

    _setup_logging(args.verbosity)
    _banner()

    # --sbom ingest mode replaces the directory target with the document:
    # there is no source tree, so the isdir guard below must not apply and
    # every source-walking engine is skipped further down.
    sbom_ingest_doc = None
    if args.sbom:
        from scanner.sbom_reader import SbomReadError, ingest_sbom

        sbom_file = os.path.abspath(args.sbom)
        if not os.path.isfile(sbom_file):
            _safe_print_error(f"  [ERROR] SBOM file does not exist: {sbom_file}")
            sys.exit(2)
        _step("Ingesting SBOM", os.path.basename(sbom_file))
        try:
            sbom_ingest_doc = ingest_sbom(sbom_file)
        except SbomReadError as exc:
            _safe_print_error(f"  [ERROR] {exc}")
            sys.exit(2)
        _safe_print(
            f"       => {len(sbom_ingest_doc['components'])} components "
            f"({sbom_ingest_doc['format']} {sbom_ingest_doc['spec_version']})"
        )
        target_path = Path(sbom_file)
        target = str(target_path)
    else:
        target_path = Path(os.path.abspath(args.target))
        target = str(target_path)

        if not os.path.exists(target):
            _safe_print_error(f"  [ERROR] Target path does not exist: {target}")
            sys.exit(2)

        if not os.path.isdir(target):
            _safe_print_error(f"  [ERROR] Target path is not a directory: {target}")
            sys.exit(2)

    # V17.9.x: project-isolated report output. By default every scan gets its
    # own directory under a sibling `reports` folder:
    #   <validation-root>/<project>/
    #   <validation-root>/reports/<project>/
    # This prevents one project's artifacts from overwriting another project's
    # reports. An explicit --output-dir/-o remains available as an override.
    project_name = (target_path.stem if sbom_ingest_doc is not None
                    else target_path.name)
    if args.output_dir:
        output_dir = Path(os.path.abspath(args.output_dir))
    elif sbom_ingest_doc is not None:
        # Ingest mode has no project directory: keep reports under the
        # working directory instead of beside someone else's SBOM file.
        output_dir = Path.cwd() / "reports" / project_name
    else:
        output_dir = target_path.parent / "reports" / project_name
    output_dir.mkdir(parents=True, exist_ok=True)
    scan_log_path = _attach_scan_log(output_dir)

    _safe_print(f"  Tool root : {_HERE}")
    _safe_print(f"  Project   : {project_name}")
    _safe_print(f"  Target    : {target}")
    _safe_print(f"  Output    : {output_dir}")
    _safe_print(f"  Workers   : {args.workers}")
    _safe_print("")

    t0 = time.time()
    _timing_start_scan()

    if sbom_ingest_doc is not None:
        raw = []
        _safe_print("  [i] SBOM ingest mode: source scan skipped "
                    "(no source tree to scan)")
    else:
        _step("Scanning codebase", f"regex + AST taint, {args.workers} workers")
        from scanner.sast import scan_directory

        raw = scan_directory(target, workers=args.workers)
        _safe_print(f"       => {len(raw)} raw findings in {time.time() - t0:.1f}s")

    if sbom_ingest_doc is None:
        _step("Generating SBOM & dependency analysis")
        from scanner.sbom import generate_sbom

        sbom = generate_sbom(target)
    else:
        sbom = sbom_ingest_doc["components"]

    # Advisory-lookup disclosure. The SCA numbers below are only meaningful if the
    # external CVE lookup actually happened: an unreachable OSV yields the same
    # package list with zero CVEs, which would otherwise read as a clean bill of
    # health. The status is captured here so the warning can be printed next to the
    # SBOM line that produced it, and attached to the payload further down -- the
    # payload does not exist yet at this point in main(), it is built later by
    # build_report_payload().
    from scanner.sbom import advisory_service_status as _advisory_status

    advisory_status = _advisory_status()
    if not advisory_status.get("available", True):
        _safe_print("       => WARNING: external advisory lookup (OSV) did not "
                    "complete; CVE counts in this report are INCOMPLETE. "
                    f"{advisory_status.get('coverage_note') or advisory_status.get('error', '')}")

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

    # Ingest mode: the source SBOM may carry its own declared dependency
    # relationships. They are the source document's claims (not ours), so
    # the engine label says exactly that; without them the graph stays the
    # empty NO_VERIFIED_EDGES skeleton from above.
    if (sbom_ingest_doc is not None
            and sbom_ingest_doc.get("dependencies")):
        declared = sbom_ingest_doc["dependencies"]
        dependency_graph = {
            "engine": "SBOM_INGEST_RELATIONSHIPS",
            "graph_status": "DECLARED_IN_SOURCE_SBOM",
            "verified_edge_count": sum(
                len(d.get("depends_on") or []) for d in declared),
            "edges": declared,
            "evidence_policy": "SOURCE_SBOM_DECLARED_RELATIONSHIPS",
            "sources": [sbom_ingest_doc["source_file"]],
        }
        _safe_print(
            "       => Dependency graph: "
            f"{dependency_graph['verified_edge_count']} declared edges "
            "(from the ingested SBOM)"
        )

    vuln_deps = [d for d in sbom if d.get("cve")]
    vuln_deps = [d for d in sbom if d.get("cve")]
    _safe_print(f"       => {len(sbom)} packages, {len(vuln_deps)} with known CVEs")

    # Ingest mode: there is no source tree. Every engine below walks the
    # target path; against an SBOM file they would either do nothing or
    # (worse) scan the SBOM document itself -- the secrets scanner reads
    # .json files, so ingesting a third party's SBOM must not produce
    # "findings" from its bytes. The whole engine block is skipped; raw
    # stays [] and every inventory is empty by construction.
    if sbom_ingest_doc is not None:
        _safe_print("  [i] SBOM ingest mode: code/IaC/secret/AI engines skipped")

    if sbom_ingest_doc is None:
        _step("Generating CBOM crypto inventory")
        cbom = generate_cbom(target)
        _safe_print(f"       => {len(cbom)} crypto assets identified")

        _step("Generating AI-BOM model/provider inventory")
        aibom = generate_aibom(target)
        _safe_print(f"       => {len(aibom)} AI assets identified")

        # Phase 4.3: HuggingFace hub metadata enrichment for detected
        # model usages (fail-open, cached; RSX_HF_ENRICH=0 disables).
        try:
            from scanner.aibom import enrich_hf_metadata
            aibom = enrich_hf_metadata(aibom)
            hf_ok = sum(1 for i in aibom
                        if (i.get("hf_enrichment") or {}).get("status") == "ok")
            if hf_ok:
                _safe_print(
                    f"       => {hf_ok} HuggingFace model(s) enriched from the hub")
        except Exception as exc:
            _safe_print(f"       => HF enrichment skipped: {exc}")

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
    else:
        cbom = aibom = mlbom = apibom = abom = []
        k8s_findings = tf_findings = docker_findings = []
        llm_raw_findings = llm_findings = advanced_ai_findings = []
        api_abuse_findings = secret_scan_findings = []
        llm_precision_stats = {"actionable": 0, "contextual": 0}

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

    # Report both sides of the context classification, and name the population
    # these counts describe. They are measured here, before report
    # construction, so they are a *pre-dedup* reading; the same three numbers
    # are re-printed at the serialization boundary against the population that
    # is actually written, so the two lines can be reconciled instead of
    # silently disagreeing with clean_report.json.
    synthetic_marked = sum(
        1 for f in raw if str(f.get("analysis_scope") or "") == "benchmark_synthetic"
    )
    synthetic_excluded = sum(1 for f in raw if f.get("suppressed_from_primary_count"))
    _safe_print(
        "       => Analysis Context (raw, pre-dedup): "
        f"{synthetic_marked} of {len(raw)} findings are benchmark-synthetic | "
        f"{synthetic_excluded} suppressed from primary count"
    )

    payload = build_report_payload(raw, sbom, target)

    # Now that the payload exists, attach the advisory-lookup disclosure computed
    # at SBOM time. Every downstream report can then tell "no known
    # vulnerabilities" from "the vulnerability database could not be reached" --
    # which is the difference between a clean bill of health and a gap in the scan.
    payload["sbom_advisory_status"] = advisory_status

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
    # PROVISIONAL. Later enrichment phases still attach mappings to individual
    # findings, so this snapshot goes stale: measured on the Juice Shop corpus
    # (report 06102026 1914) it reported CWE 21 / OWASP 21 / PCI DSS 19 while
    # the written findings[] held 22 / 22 / 20. It is recomputed against the
    # final population immediately before serialization -- see the
    # compliance_summary block next to the SSDF alignment. Kept here because
    # intermediate phases read it.
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

    # ------------------------------------------------------------------
    # Both QBOM layers are computed HERE, not in the report stage.
    #
    # They were originally built immediately before the Excel reports, which is
    # AFTER generate_pdf_report() runs. The result was that every PDF rendered the
    # post-quantum section as "No post-quantum exposure assessment was produced for
    # this scan" while clean_report.json on the same run carried a populated
    # layer -- the artifacts and the payload disagreed about whether the scan had
    # an assessment. Computed early, the payload is authoritative and every
    # renderer sees the same data; the report stage only writes files.
    # ------------------------------------------------------------------
    _qbom_docs = _build_qbom_layers(payload)

    # --------------------------------------------------
    # G-004: cross-BOM correlation.
    # `scanner/aibom_abom_correlation.correlate()` was built and unit-tested
    # but never imported by the scan pipeline, so no product output ever
    # contained it (root-cause class WIRING_GAP).  5h identity gating makes
    # it safe to run: an agent is linked only to the model it declares, so
    # no edge is manufactured from textual proximity.
    #
    # Correlation is advisory evidence.  It never gates, suppresses or
    # reclassifies a finding, and an engine failure degrades to an empty
    # relationship set that is *recorded* as DEGRADED -- an absence of
    # relationships must never be laundered into a positive claim that none
    # exist.
    # --------------------------------------------------
    _step("AI-BOM <-> ABOM correlation")
    try:
        _bom_links = correlate_aibom_abom(
            abom=payload.get("abom", []),
            aibom=payload.get("aibom", []),
        )
        if not isinstance(_bom_links, list):
            raise TypeError(f"correlate() returned {type(_bom_links).__name__}")
        _bom_corr_status = "CORRELATED"
        _bom_corr_error = ""
    except Exception as exc:  # correlation must never fail a scan
        _bom_links = []
        _bom_corr_status = "DEGRADED"
        _bom_corr_error = f"{type(exc).__name__}: {exc}"

    _bom_corr_by_type: dict[str, int] = {}
    for _rel in _bom_links:
        if isinstance(_rel, dict):
            _rt = str(_rel.get("relationship_type") or "UNKNOWN")
            _bom_corr_by_type[_rt] = _bom_corr_by_type.get(_rt, 0) + 1

    payload["bom_correlation"] = _bom_links
    payload["bom_correlation_summary"] = {
        "status": _bom_corr_status,
        "error": _bom_corr_error,
        "relationships": len(_bom_links),
        "by_relationship_type": _bom_corr_by_type,
        "abom_items": len(payload.get("abom") or []),
        "aibom_items": len(payload.get("aibom") or []),
        "detection": "CROSS_BOM_CORRELATION_V1",
    }
    _safe_print(
        "       => BOM correlation: "
        f"{len(_bom_links)} relationship(s) | "
        f"status: {_bom_corr_status}"
    )

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
    if sbom_ingest_doc is not None:
        # Ingest mode has no source tree: undeclared-dependency comparison
        # and reachability both walk the target directory, which does not
        # exist here. Skip BOTH with disclosure rather than scoring zero.
        payload["reachability_summary"] = {
            "status": "skipped",
            "reason": "sbom_ingest_mode_has_no_source_tree",
        }
        payload["reachability_vulnerability_summary"] = {}
        payload["reachability_references_count"] = 0
    else:
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

    # G-001/G-002: resolve the live feed pair once per process.  A ``None``
    # member means the operator opted out; a feed that is unreachable degrades
    # inside its engine to the compiled-in seed table.  Either way a scan must
    # never fail, hang or change a finding because a feed is.
    _feeds = default_feed()

    _step("KEV intelligence")
    payload["sbom"] = enrich_kev_intelligence(
        payload.get("sbom", []), feed=_feeds.kev
    )
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
    payload["sbom"] = enrich_epss_intelligence(
        payload.get("sbom", []), feed=_feeds.epss
    )
    payload["epss_intelligence_summary"] = epss_intelligence_summary(
        payload.get("sbom", [])
    )

    # Report where the numbers above actually came from - operator-visible,
    # not buried in a JSON key nobody reads.
    _eis_live = bool(payload["epss_intelligence_summary"].get("live_feeds_used"))
    _kis_live = bool(payload["kev_intelligence_summary"].get("live_feeds_used"))
    if _eis_live or _kis_live:
        _safe_print(
            "       => Live intel feeds: EPSS "
            f"{'LIVE' if _eis_live else 'seed table'}, "
            f"KEV {'LIVE' if _kis_live else 'seed table'}"
            + (
                f" (catalog {payload['kev_intelligence_summary'].get('catalog_version')})"
                if _kis_live and payload["kev_intelligence_summary"].get("catalog_version")
                else ""
            )
        )
    else:
        _safe_print(
            "       => Live intel feeds: unavailable or disabled - using "
            "compiled-in seed tables (provenance stays "
            f"{STATIC_REFERENCE})"
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

    # `sbom_summary.license_risks` was frozen at the package-intelligence
    # step, which runs *before* enrich_license_policy rewrites `license_risk`.
    # Recompute it from the final policy-enriched list so the summary, its
    # `metadata` mirror and `license_policy_summary.risk_counts` cannot
    # disagree (it previously read 0 while 48 components were MEDIUM).
    _license_risk_count = license_risk_count(payload.get("sbom", []))
    _sbom_summary = payload.get("sbom_summary")
    if isinstance(_sbom_summary, dict):
        _sbom_summary["license_risks"] = _license_risk_count
    _metadata = payload.get("metadata")
    if isinstance(_metadata, dict):
        _metadata["license_risks"] = _license_risk_count

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

    # Phase 2: attached HERE, after the LAST payload["sbom"] mutation
    # (runtime artifact integrity above), so the quality score and the
    # baseline delta are computed against the FINAL inventory -- KEV/EPSS/
    # licence/trust enrichment included -- not an intermediate state.

    # Ingest provenance, so every downstream emitter and a reader of
    # clean_report.json can tell this inventory came from a file rather
    # than from a source scan.
    if sbom_ingest_doc is not None:
        payload["sbom_ingest"] = {
            "scan_mode": "sbom_ingest",
            "source_file": sbom_ingest_doc["source_file"],
            "format": sbom_ingest_doc["format"],
            "spec_version": sbom_ingest_doc["spec_version"],
            "serial_number": sbom_ingest_doc["serial_number"],
            "created": sbom_ingest_doc["created"],
            "tools": sbom_ingest_doc["tools"],
            "component_count": len(payload.get("sbom") or []),
            "declared_vulnerability_records": len(
                sbom_ingest_doc.get("vulnerabilities") or []),
            "warnings": sbom_ingest_doc.get("warnings") or [],
        }
        payload.setdefault("metadata", {})["scan_mode"] = "sbom_ingest"

    # sbomqs-style quality score. Offline factors only; what cannot be
    # honestly computed from the document is listed as not_covered rather
    # than guessed (analysis/sbom_quality.py).
    from analysis.sbom_quality import score_sbom as _score_sbom
    payload["sbom_quality"] = _score_sbom(
        payload.get("sbom") or [],
        doc=sbom_ingest_doc,
        dependency_edges=(payload.get("dependency_graph") or {}).get("edges"),
        generated_at=(payload.get("metadata") or {}).get("scan_date"),
        tools=["R-SecOpsX"],
        advisory_checked=bool(advisory_status.get("available", True)),
    )
    _safe_print(
        f"       => SBOM quality: {payload['sbom_quality']['score']}/100 "
        f"(grade {payload['sbom_quality']['grade']}, "
        f"{payload['sbom_quality']['component_count']} components)"
    )

    # Optional baseline delta (works in both scan and ingest modes).
    # Report-only; a broken baseline must never fail the run.
    if args.baseline:
        try:
            from scanner.sbom_baseline import diff_baseline as _diff_baseline
            payload["baseline_diff"] = _diff_baseline(
                payload.get("sbom") or [], args.baseline)
            _bsum = payload["baseline_diff"]["summary"]
            _safe_print(
                "       => baseline: +%d ~%d -%d components, "
                "%d new / %d resolved advisories"
                % (_bsum["added"], _bsum["changed"], _bsum["removed"],
                   _bsum["vulnerabilities_new"],
                   _bsum["vulnerabilities_resolved"])
            )
        except (OSError, ValueError, TypeError) as exc:
            payload["baseline_diff"] = {"status": "error", "error": str(exc)}
            _safe_print(f"       => WARNING: baseline diff unavailable: {exc}")

    
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
    if sbom_ingest_doc is not None:
        # Ingest mode: the privacy engine's _iter_files() YIELDS a lone
        # file when its suffix is scannable (.json is) -- against an SBOM
        # path that would read the document's own bytes and report PII
        # "indicators" extracted from someone else's component names.
        # Skipped with disclosure rather than scoring zero silently.
        payload["privacy_data_exposure_summary"] = {
            "summary_status": "SKIPPED",
            "reason": "sbom_ingest_mode_has_no_source_tree",
            "total_privacy_indicators": 0,
        }
    else:
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
            # G-003: consumers read this sub-array directly, so carry the label.
            "kev_provenance": pkg.get("kev_provenance") or STATIC_REFERENCE,
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
    _refresh_supply_chain_insight(payload)


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
    # G-003: one authoritative statement, at the top of the JSON payload, that
    # EPSS/KEV are offline snapshots rather than live FIRST.org / CISA feeds.
    _apply_epss_kev_provenance_banner(payload, kis, eis)
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

    # Optional benchmark enrichment: Juice Shop challenge declarations are
    # ground-truth metadata only; they never suppress or downgrade findings.
    _step("Final benchmark metadata enrichment")
    payload = enrich_juice_shop_ground_truth(payload, target)
    _gt = (payload.get("metadata") or {}).get("benchmark_ground_truth") or {}
    if _gt.get("ground_truth_source_status") == "LOADED":
        # Recall is published next to the finding counts so the denominator is
        # never lost: 15 declared-intentional findings means little without
        # knowing the inventory held 116 challenges.
        _safe_print(
            "       => Ground truth coverage: "
            f"{_gt.get('challenges_covered_count', 0)}/{_gt.get('challenges_total', 0)} challenges mapped "
            f"| recall {_gt.get('challenge_recall', 0.0):.4f} | "
            f"{_gt.get('declared_intentional_findings', 0)} declared-intentional findings | "
            f"{_gt.get('unresolved_findings', 0)} unresolved findings"
        )

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
    # Silent (no _step) so the Scan_Performance phase inventory is unchanged:
    # owasp/mitre/insights are rebuilt from the final finding population.
    payload = _rebuild_finding_derived_aggregates(payload)

    # Console summary is printed ONLY after every payload mutation has
    # finished. The integrity, noise and safety passes above can drop
    # findings, re-score severity and recompute total_findings/risk_score,
    # so printing this block earlier reported "1439 unique findings" and a
    # severity table that disagreed with the clean_report.json written
    # immediately afterwards (1290 findings / 1293 total on Juice Shop).
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

    # Normalise insight counts ONCE, against the same distribution the severity
    # table below prints. reporting/pdf_report.py and reporting/excel_report.py
    # already call normalize_report_insights(), but the console (main.py
    # "INTELLIGENCE INSIGHTS") and clean_report.json read payload["insights"]
    # raw, so a single scan published two different totals in different
    # deliverables: on Juice Shop the console and JSON said "COMPLIANCE RISK:
    # 2 Critical/High findings" while Security_Report.pdf said 5, and the
    # "HIGH RISK: 2" insight sat directly beneath a severity table reading
    # High 4. Applying it here makes every artifact agree by construction, and
    # the renderers re-applying it is idempotent.
    try:
        from reporting.report_mappings import normalize_report_insights
        if isinstance(payload.get("insights"), list):
            payload["insights"] = normalize_report_insights(payload["insights"], dist)
    except Exception:
        # Fail open on the insight sentence only: insights are presentation,
        # and dropping the report to reconcile one line would be the wrong
        # trade. No finding, score or release decision is derived from this.
        pass

    # One canonical release decision for every output renderer.
    canonical_release = (payload.get("release_readiness", {}) or {}).get("release_decision") or meta.get("release_readiness_decision") or (payload.get("executive_decision", {}) or {}).get("executive_decision") or meta.get("executive_decision") or "UNKNOWN"
    meta["canonical_release_decision"] = canonical_release
    risk = meta["risk_score"]
    total = meta["total_findings"]
    paths = len(payload.get("attack_paths", []))

    # risk / total / paths are computed here, next to the canonical release
    # decision, but they are PRINTED at the very end of the console (after the
    # performance table, output file list and insights). A reader should not
    # have to scroll back minutes of report-generation output to find the
    # verdict. They still come from the payload that is actually serialized --
    # see test_console_summary_runs_after_every_payload_mutation, which pins
    # every payload mutation to before the print.
    #
    # The Analysis Context figures are computed later, at the print site, so
    # they are measured against the population that is written.

    # NIST SSDF (SP 800-218) evidence alignment.
    #
    # Computed HERE, immediately before serialization, not earlier: the probes
    # reference sbom, kev_intelligence_summary, release_readiness and others,
    # and an earlier evaluation silently under-reports because those sections
    # are not yet attached. That was measured: computing it next to
    # v11_intelligence observed 1 of 15 practices on a Juice Shop scan where
    # the completed artifact supports 6.
    #
    # SSDF is a process framework, so this attaches NO practice identifier to
    # any finding. Each practice is marked OBSERVED / NOT_OBSERVED /
    # NOT_ATTESTABLE_BY_A_SCANNER against a concrete artifact path.
    # Fails open: an alignment error must never drop the report.
    try:
        from core.ssdf_mappings import evaluate_ssdf_alignment as _eval_ssdf

        payload["ssdf_alignment"] = _eval_ssdf(payload)
    except Exception as _ssdf_error:
        payload["ssdf_alignment"] = {
            "status": "REVIEW_REQUIRED",
            "error": str(_ssdf_error),
        }

    # Compliance summary, recomputed against the population that is actually
    # written. Same reasoning as the SSDF block above and for the same reason:
    # the mid-pipeline snapshot at "Compliance enrichment" predates later
    # per-finding enrichment, so the report used to state one PCI DSS count in
    # compliance_summary and a different one in findings[].
    #
    # `compliance_summary_detail` carries the unit and the generic-vs-specific
    # split, because the bare int map cannot be read as coverage: three
    # frameworks are applied to every finding by GENERIC_MAPPING.
    # Reconciling this against the flat per-finding string fields and the
    # executive-PDF "Observed Mappings" column is G-064 and stays open -- no
    # measure is promoted to authoritative here.
    try:
        _final_findings = payload.get("findings", [])
        payload["compliance_summary"] = compliance_summary(_final_findings)
        payload["compliance_summary_detail"] = compliance_summary_detail(
            _final_findings
        )
    except Exception as _compliance_summary_error:
        payload.setdefault("compliance_summary_detail", {})["status"] = (
            "REVIEW_REQUIRED"
        )
        payload["compliance_summary_detail"]["error"] = str(
            _compliance_summary_error
        )

    # OWASP ASVS v4.0.3 requirement-level attribution.
    #
    # Applied HERE, immediately before serialization, for the same reason as the
    # SSDF block: the finding's CWE is not final until every enrichment phase has
    # run, and ASVS's entire mapping is keyed on CWE. Computing it earlier
    # attributes requirements to a pre-enrichment population.
    #
    # What a mapped requirement means, because the temptation to overstate this
    # is the whole risk: an ASVS requirement is a "Verify that ..." statement
    # established by testing an application. A finding attached to it means the
    # finding is EVIDENCE RELEVANT to that requirement. It does not mean the
    # requirement is unmet, and it is not an ASVS compliance claim. The 268
    # requirements ASVS gives a CWE edge are the ones whose subject is a
    # detectable weakness class; the other 10 are not reachable by a source scan.
    #
    # Fails open per finding and as a whole: an ASVS error must never drop the
    # report, and one unmappable finding must never drop the other 101.
    try:
        from core.asvs_mappings import (
            asvs_coverage as _asvs_coverage,
            enrich_with_asvs as _enrich_asvs,
            unreferenced_cwe as _asvs_unreferenced,
        )

        _asvs_findings = payload.get("findings", [])
        _asvs_cwes = []
        _asvs_vtypes = []
        _asvs_mapped = 0
        _asvs_unmapped = 0
        for _f in _asvs_findings:
            if not isinstance(_f, dict):
                continue
            try:
                _enrich_asvs(_f)
            except Exception:
                # A single finding that cannot resolve stays un-attributed, and
                # says so, rather than aborting the pass.
                _f["asvs_mapping_mode"] = "UNMAPPED"
                _f["asvs_rationale"] = "ASVS resolution failed for this finding."
            # Count mapped and unmapped SEPARATELY. Counting "any resolution" as
            # attributed would report 7 attributed on a corpus where 5 resolved
            # to UNMAPPED, which is exactly the inflation this project forbids.
            if str(_f.get("asvs_mapping_mode") or "") == "UNMAPPED":
                _asvs_unmapped += 1
            else:
                _asvs_mapped += 1
            _c = _f.get("cwe")
            if _c:
                _asvs_cwes.append(str(_c))
            _v = _f.get("vuln_type")
            if _v:
                _asvs_vtypes.append(str(_v))

        payload["asvs_summary"] = _asvs_coverage(_asvs_cwes, _asvs_vtypes)
        payload["asvs_summary"]["findings_mapped"] = _asvs_mapped
        payload["asvs_summary"]["findings_unmapped"] = _asvs_unmapped
        payload["asvs_summary"]["findings_resolved"] = _asvs_mapped + _asvs_unmapped
        payload["asvs_summary"]["unreferenced_cwe"] = _asvs_unreferenced(
            _asvs_cwes
        )
    except Exception as _asvs_error:
        payload["asvs_summary"] = {
            "status": "REVIEW_REQUIRED",
            "error": str(_asvs_error),
            "dataset": "OWASP ASVS v4.0.3",
        }

    # RBI FREE-AI traceability layer.
    #
    # Same placement rationale as ASVS: the finding's rule_id/vuln_type is not
    # final until every enrichment phase has run.
    #
    # FREE-AI is a COMMITTEE REPORT addressed to Indian financial-sector
    # regulated entities, not a binding direction, and it does not automatically
    # apply to any corpus this tool scans. Both facts are carried on every mapped
    # finding (`free_ai_legal_status`, `free_ai_applicable_to_corpus`) so a
    # report cannot present an attribution as a compliance verdict.
    #
    # 16 of its 26 recommendations are organisational acts a scan cannot observe;
    # those are reported as NOT_ATTESTABLE rather than quietly counted as covered.
    try:
        from core.free_ai_mappings import (
            enrich_with_free_ai as _enrich_free_ai,
            free_ai_coverage as _free_ai_coverage,
        )

        _freeai_findings = payload.get("findings", [])
        _freeai_rules = []
        _freeai_vtypes = []
        _freeai_mapped = 0
        _freeai_unmapped = 0
        for _f in _freeai_findings:
            if not isinstance(_f, dict):
                continue
            try:
                _enrich_free_ai(_f)
            except Exception:
                _f["free_ai_mapping_mode"] = "UNMAPPED"
                _f["free_ai_rationale"] = "FREE-AI resolution failed for this finding."
            if str(_f.get("free_ai_mapping_mode") or "") == "UNMAPPED":
                _freeai_unmapped += 1
            else:
                _freeai_mapped += 1
            _r = _f.get("rule_id")
            if _r:
                _freeai_rules.append(str(_r))
            _v = _f.get("vuln_type")
            if _v:
                _freeai_vtypes.append(str(_v))

        payload["free_ai_summary"] = _free_ai_coverage(_freeai_rules, _freeai_vtypes)
        payload["free_ai_summary"]["findings_mapped"] = _freeai_mapped
        payload["free_ai_summary"]["findings_unmapped"] = _freeai_unmapped
    except Exception as _free_ai_error:
        payload["free_ai_summary"] = {
            "status": "REVIEW_REQUIRED",
            "error": str(_free_ai_error),
            "dataset": "RBI FREE-AI Committee Report (2025-08-13)",
        }

    # SANS Critical AI Security Guidelines v1.4 traceability.
    #
    # Control identifiers are LOCALLY ASSIGNED: the guidelines number nothing, so
    # `id_origin` travels on every mapping and the report must cite these as
    # convenience handles rather than as SANS-issued identifiers. Without that
    # distinction an id like SANS-AIC-CAT5-C01 reads as authoritative numbering
    # that MITRE/SANS never issued.
    try:
        from core.sans_mappings import (
            enrich_with_sans as _enrich_sans,
            sans_coverage as _sans_coverage,
        )

        _sans_findings = payload.get("findings", [])
        _sans_rules = []
        _sans_vtypes = []
        _sans_mapped = 0
        _sans_unmapped = 0
        for _f in _sans_findings:
            if not isinstance(_f, dict):
                continue
            try:
                _enrich_sans(_f)
            except Exception:
                _f["sans_mapping_mode"] = "UNMAPPED"
                _f["sans_rationale"] = "SANS resolution failed for this finding."
            if str(_f.get("sans_mapping_mode") or "") == "UNMAPPED":
                _sans_unmapped += 1
            else:
                _sans_mapped += 1
            _r = _f.get("rule_id")
            if _r:
                _sans_rules.append(str(_r))
            _v = _f.get("vuln_type")
            if _v:
                _sans_vtypes.append(str(_v))

        payload["sans_summary"] = _sans_coverage(_sans_rules, _sans_vtypes)
        payload["sans_summary"]["findings_mapped"] = _sans_mapped
        payload["sans_summary"]["findings_unmapped"] = _sans_unmapped
    except Exception as _sans_error:
        payload["sans_summary"] = {
            "status": "REVIEW_REQUIRED",
            "error": str(_sans_error),
            "dataset": "SANS Critical AI Security Guidelines v1.4",
        }

    # OWASP Web Security Testing Guide v4.2 traceability.
    #
    # WSTG is a TESTING guide: its 97 entries are procedures against a running
    # application. A mapping means the finding is the kind of weakness a test case
    # looks for -- NOT that this scan performed the test. The coverage block keeps
    # that distinction as data (`static_attestable`, `catalogue_not_static_
    # attestable`) so a report cannot imply WSTG conformance the scan never
    # assessed. 29 of the 97 cases are runtime or interactive procedures and are
    # counted separately rather than folded into coverage.
    try:
        from core.wstg_mappings import (
            enrich_with_wstg as _enrich_wstg,
            wstg_coverage as _wstg_coverage,
        )

        _wstg_rules = []
        _wstg_mapped = 0
        _wstg_unmapped = 0
        for _f in payload.get("findings", []):
            if not isinstance(_f, dict):
                continue
            try:
                _enrich_wstg(_f)
            except Exception:
                _f["wstg_mapping_mode"] = "UNMAPPED"
                _f["wstg_rationale"] = "WSTG resolution failed for this finding."
            if str(_f.get("wstg_mapping_mode") or "") == "UNMAPPED":
                _wstg_unmapped += 1
            else:
                _wstg_mapped += 1
            _r = _f.get("rule_id")
            if _r:
                _wstg_rules.append(str(_r))

        payload["wstg_summary"] = _wstg_coverage(_wstg_rules)
        payload["wstg_summary"]["findings_mapped"] = _wstg_mapped
        payload["wstg_summary"]["findings_unmapped"] = _wstg_unmapped
    except Exception as _wstg_error:
        payload["wstg_summary"] = {
            "status": "REVIEW_REQUIRED",
            "error": str(_wstg_error),
            "dataset": "OWASP Web Security Testing Guide v4.2",
        }

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

    # --no-pdf was declared but never consulted, so the flag skipped nothing:
    # a probe scan with --no-pdf still wrote both PDFs. --no-excel, declared on
    # the adjacent line, has always been honoured below. Both large AI-corpus
    # projects time out in this phase, and clean_report.json -- which is what the
    # benchmark harness actually reads -- is written above, before this block.
    if not args.no_pdf:
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
                _REPORT_EXPORT_FAILURES.append(("Executive PDF", str(exc)))
                _safe_print(f"       => Executive PDF failed: {exc}")
        except Exception as exc:
            # ------------------------------------------------------------------
            # Exporter failures are ACCUMULATED, not just printed.
            #
            # Each exporter wraps itself in `except Exception` and prints one line.
            # That made a lost artifact invisible: BenchmarkJava-master shipped with
            # every artifact except both PDFs, because generate_pdf_report raised
            # reportlab LayoutError and the run still exited 0. A reader cannot tell
            # a report that has no PDF from one where none was asked for, so failures
            # are recorded here and reported at the end of the run.
            #
            # Fails open: an exporter that breaks must not destroy the other artifacts.
            _REPORT_EXPORT_FAILURES.append(("Security_Report.pdf", str(exc)))
            _safe_print(f"       => PDF failed: {exc}")


    # Both QBOM documents were computed in _build_qbom_layers() while the payload
    # was being assembled, which is BEFORE generate_pdf_report(). Serialisation
    # only happens here.
    #
    # That ordering is not cosmetic. When the documents were built at this point,
    # every PDF rendered the post-quantum section as "No post-quantum exposure
    # assessment was produced for this scan" while clean_report.json for the same
    # run carried a populated layer. The PDF is generated earlier in main(), so
    # anything a payload key holds at this point is invisible to it.
    #
    # CERT-In defines SBOM / QBOM / CBOM / AIBOM / HBOM as distinct BOM types with
    # distinct minimum-element tables, so the two documents stay separate artifacts
    # with separate payload keys. Correction kept on the record: this layer was
    # earlier mis-described as a "Quality" BOM; CERT-In v2.0 Chapter 8.1 defines
    # QBOM as the Quantum Bill of Materials, and core/qbom_mappings.py quotes the
    # definition from the pinned PDF rather than paraphrasing it.
    try:
        import json as _bom_json

        _certin = _qbom_docs.get("certin")
        if _certin is not None:
            _qbom_path = output_dir / "Security_QBOM.qbom.json"
            _qbom_path.write_text(
                _bom_json.dumps(_certin, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8")
            generated_files.append(_qbom_path.name)
            _safe_print(f"       => {_qbom_path}  "
                        f"({_certin['element_coverage']['observable_from_source']}/"
                        f"{_certin['element_coverage']['minimum_elements']} Table 8 "
                        f"elements observable from source; "
                        f"quantum components detected: "
                        f"{_certin['quantum_components_detected']})")
        elif _qbom_docs.get("errors", {}).get("certin"):
            _safe_print(f"       => CERT-In QBOM unavailable: "
                        f"{_qbom_docs['errors']['certin']}")

        _pq = _qbom_docs.get("pq")
        if _pq is not None:
            _exposure = _pq["exposure_summary"]
            _pq_path = output_dir / "Security_QBOM.pq.json"
            _pq_path.write_text(
                _bom_json.dumps(_pq, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8")
            generated_files.append(_pq_path.name)
            _safe_print(f"       => {_pq_path}  "
                        f"({_exposure['total_usage_sites']} usage sites -> "
                        f"{_exposure['total_assets']} assets; "
                        f"{len(_exposure['migration_queue'])} need migration; "
                        f"{_exposure['unclassified']} unclassified)")
        elif _qbom_docs.get("errors", {}).get("pq"):
            _safe_print(f"       => PQ QBOM unavailable: "
                        f"{_qbom_docs['errors']['pq']}")

        # A build error is a disclosed gap, not a silent one. It is recorded here as
        # well as in the payload so it appears in the run's own report of failures
        # rather than only inside the document.
        for _name in ("certin", "pq"):
            _err = _qbom_docs.get("errors", {}).get(_name)
            if _err:
                _REPORT_EXPORT_FAILURES.append(
                    ("Security_QBOM.qbom.json" if _name == "certin"
                     else "Security_QBOM.pq.json", _err))
    except Exception as _bom_write_error:
        # Writing the JSON must not take the run down. The documents are already
        # in the payload, so the loss is limited to the standalone files.
        _REPORT_EXPORT_FAILURES.append(
            ("Security_QBOM.*.json", f"{type(_bom_write_error).__name__}: "
                                     f"{_bom_write_error}"))
        _safe_print(f"       => QBOM artifact write failed: {_bom_write_error}")

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

    _step("Generating SPDX report")
    try:
        from reporting.spdx_export import write_spdx_report

        spdx_path = output_dir / "Security_SPDX.spdx.json"
        write_spdx_report(payload, str(spdx_path))
        generated_files.append(spdx_path.name)
        _safe_print(f"       => {spdx_path}")
    except Exception as exc:
        _safe_print(f"       => SPDX failed: {exc}")

    # ------------------------------------------------------------------
    # CycloneDX 1.6 CBOM / AI-BOM (Phase 4).
    #
    # The main SBOM above is specVersion 1.5, which predates the
    # cryptographic-asset component type and the cryptoProperties object;
    # embedding the crypto inventory there yields opaque data components.
    # These two documents use 1.6 so a CBOM/AI-BOM consumer sees real
    # algorithm/protocol/material assets. They are separate artifacts for
    # the same reason the CERT-In QBOM is: distinct BOM types with
    # distinct consumers.
    # ------------------------------------------------------------------
    _step("Generating CycloneDX CBOM report")
    try:
        from reporting.cyclonedx_bom_export import write_cbom_report

        cbom_cdx_path = output_dir / "Security_CBOM.cdx.json"
        write_cbom_report(payload.get("cbom") or [], str(cbom_cdx_path),
                          target_name=project_name)
        generated_files.append(cbom_cdx_path.name)
        _safe_print(f"       => {cbom_cdx_path}")
    except Exception as exc:
        _safe_print(f"       => CBOM (CycloneDX 1.6) failed: {exc}")

    _step("Generating CycloneDX AI-BOM report")
    try:
        from reporting.cyclonedx_bom_export import write_aibom_report

        aibom_cdx_path = output_dir / "Security_AIBOM.cdx.json"
        write_aibom_report(payload.get("aibom") or [], str(aibom_cdx_path))
        generated_files.append(aibom_cdx_path.name)
        _safe_print(f"       => {aibom_cdx_path}")
    except Exception as exc:
        _safe_print(f"       => AI-BOM (CycloneDX 1.6) failed: {exc}")

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

    # ------------------------------------------------------------------
    # Security gate metadata.  Same boundary as scan_timing above: after
    # every renderer has run, so payload["findings"] is the population the
    # artefacts actually describe and the gate is measured against the same
    # list the reader is given.  Computed once here and reused for the exit
    # code, so the file and the caller can never disagree.
    # ------------------------------------------------------------------
    security_gate = _record_security_gate(payload, args.fail_on)
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
        _safe_print(f"       => security gate persisted to {json_path}")
    except Exception as exc:
        _safe_print(f"       => security gate persistence failed: {exc}")

    # ---------------------------------------------------------------
    # Persist authoritative scan-performance artifact
    # ---------------------------------------------------------------
    scan_performance_path = output_dir / "Scan_Performance.json"

    try:
        scan_performance_payload = {
            "schema_version": "1.0",
            "tool": TOOL_FULL,
            "scan_start": scan_timing.get("started_at"),
            "scan_end": scan_timing.get("completed_at"),
            "total_seconds": scan_timing.get("total_seconds"),
            "total_duration": scan_timing.get("total_duration"),
            "phases": [
                {
                    "phase": item.get("stage"),
                    "start": item.get("start_at"),
                    "end": item.get("end_at"),
                    "elapsed_seconds": item.get("seconds"),
                    "elapsed": _format_duration(item.get("seconds", 0)),
                    "gap_seconds": item.get("gap_seconds", 0),
                    "gap_from_previous_end": _format_duration(
                        item.get("gap_seconds", 0)
                    ),
                }
                for item in scan_timing.get("stages", [])
            ],
        }

        with open(
            scan_performance_path,
            "w",
            encoding="utf-8",
        ) as performance_file:
            json.dump(
                scan_performance_payload,
                performance_file,
                indent=2,
                ensure_ascii=False,
                default=str,
            )

        generated_files.append(scan_performance_path.name)

        _safe_print(
            f"       => {scan_performance_path}"
        )

    except Exception as exc:
        _safe_print(
            f"       => Scan performance artifact failed: {exc}"
        )
    # ---------------------------------------------------------------
    # Final phase — Package generated security assessment reports
    # ---------------------------------------------------------------
    _step("Packaging security assessment reports")

    target_name = Path(target).name

    report_archive = _create_security_report_archive(
        output_dir=output_dir,
        target_name=target_name,
        generated_files=generated_files,
    )

    total_time = scan_timing["total_seconds"]
    _safe_print(f"\n  [DONE]  Scan complete in {total_time:.1f}s\n")
    _safe_print("  Output files:")

    for fname in generated_files:
        p = output_dir / fname
        if p.exists():
            _safe_print(f"       {fname:<35} ({p.stat().st_size / 1024:.1f} KB)")

    # A missing artifact must be stated, not implied by its absence from the list
    # above. BenchmarkJava-master is the reason: it shipped every format except
    # both PDFs, exited 0, and said nothing.
    if _REPORT_EXPORT_FAILURES:
        _safe_print("\n  REPORT EXPORT FAILURES -- the scan completed, but these "
                    "artifacts were NOT written:")
        for _name, _reason in _REPORT_EXPORT_FAILURES:
            _safe_print(f"       MISSING  {_name:<24} {_reason[:120]}")
        _safe_print("       Treat the report as incomplete. Re-run to produce "
                    "them, or read clean_report.json for the full findings.")

    _safe_print("\n  INTELLIGENCE INSIGHTS:")
    for ins in payload.get("insights", []):
        _safe_print(f"    * {ins}")

    # ------------------------------------------------------------------
    # FINAL RESULTS -- deliberately the last thing on the console.
    # Everything above this point (per-phase logging, the performance table,
    # the output file list) is process narration. The reader's actual answer
    # belongs at the bottom of the scroll, and every number here is measured
    # against the payload that was written to clean_report.json.
    # ------------------------------------------------------------------
    _final_findings = payload.get("findings") or []
    _final_synthetic = sum(
        1 for f in _final_findings
        if isinstance(f, dict) and str(f.get("analysis_scope") or "") == "benchmark_synthetic"
    )
    _final_suppressed = sum(
        1 for f in _final_findings
        if isinstance(f, dict) and f.get("suppressed_from_primary_count")
    )
    _final_preserved = sum(
        1 for f in _final_findings
        if isinstance(f, dict) and f.get("preserved_for_evaluation")
    )

    _safe_print("")
    _safe_print("=" * 74)
    _safe_print("  FINAL RESULTS")
    _safe_print("=" * 74)
    _safe_print(
        f"       => {total} unique findings | Risk: {risk}/100 | "
        f"Attack Paths: {paths}"
    )
    _print_dist(dist)
    _safe_print(
        "       => Analysis Context (final report): "
        f"{_final_synthetic} of {len(_final_findings)} findings are benchmark-synthetic | "
        f"{_final_suppressed} suppressed from primary count | "
        f"{_final_preserved} preserved for evaluation"
    )
    _safe_print(f"       => Report: {json_path}")
    _safe_print("=" * 74)
    _safe_print("")

    # ------------------------------------------------------------------
    # Security gate.  Deliberately after the FINAL RESULTS block: the exit
    # code is for the caller (CI), the scroll above is for the reader.
    # ------------------------------------------------------------------
    # The very object written into clean_report.json, so the exit code and the
    # artefact cannot report different answers about the same scan.
    gate = security_gate
    if gate["threshold"] is None:
        _safe_print(
            "  SECURITY GATE: not requested -- pass --fail-on "
            "critical|high|medium to fail the run on findings at or above a "
            "severity"
        )
    elif gate["security_gate_passed"]:
        _safe_print(
            f"  SECURITY GATE: PASSED -- no finding at or above "
            f"{gate['threshold']}"
        )
    else:
        detail = ", ".join(
            f"{n} {sev}" for sev, n in gate["blocking_counts"].items()
        )
        _safe_print(
            f"  SECURITY GATE: FAILED -- {gate['total_blocking']} finding(s) "
            f"at or above {gate['threshold']} ({detail})"
        )
    if gate["unrecognised_severities"]:
        _safe_print(
            f"  SECURITY GATE: "
            f"{sum(gate['unrecognised_severities'].values())} finding(s) "
            f"carried a severity this gate does not recognise and were not "
            f"counted: {gate['unrecognised_severities']}"
        )
    _safe_print("")

    if not gate["security_gate_passed"]:
        # 1 = "findings at or above the requested severity".  2 stays reserved
        # for usage errors, so a caller can tell a failing scan from a
        # mistyped command line.
        sys.exit(1)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()














