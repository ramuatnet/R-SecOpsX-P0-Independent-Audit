from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent
ACADEMIC = ROOT.parent / "R-SecOpsX-Academic"

ACADEMIC_FILES = [
    "main.py",

    "core/__init__.py",
    "core/config.py",
    "core/path_utils.py",
    "core/deduplicator.py",
    "core/analyzer.py",
    "core/risk_scorer.py",
    "core/attack_graph.py",

    "scanner/__init__.py",
    "scanner/sast.py",
    "scanner/taint_engine.py",
    "scanner/sbom.py",
    "scanner/reachability.py",
    "scanner/dependency_intelligence.py",
    "scanner/package_intelligence.py",
    "scanner/compliance_mapper.py",
    "scanner/vulnerability_intel.py",
    "scanner/vulnerability_overrides.py",

    "analysis/__init__.py",
    "analysis/dependency_intelligence.py",
    "analysis/kev_intelligence_engine.py",
    "analysis/epss_intelligence_engine.py",
    "analysis/vulnerability_age_engine.py",
    "analysis/exploitability_decision_engine.py",
    "analysis/release_readiness_engine.py",

    "reporting/__init__.py",
    "reporting/sarif_export.py",
    "reporting/vex_export.py",
    "reporting/cyclonedx_export.py",
    "reporting/pdf_report.py",
    "reporting/excel_report.py",
    "reporting/report_mappings.py",
]

DIRS = [
    "core",
    "scanner",
    "analysis",
    "reporting",
    "datasets",
    "docs",
    "tests",
    "reports",
]

def copy_file(rel_path: str):
    src = ROOT / rel_path
    dst = ACADEMIC / rel_path

    if not src.exists():
        print(f"[SKIP] Missing: {rel_path}")
        return

    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    print(f"[COPY] {rel_path}")

def main():
    if ACADEMIC.exists():
        print(f"[INFO] Removing old academic folder: {ACADEMIC}")
        shutil.rmtree(ACADEMIC)

    ACADEMIC.mkdir(parents=True, exist_ok=True)

    for d in DIRS:
        (ACADEMIC / d).mkdir(parents=True, exist_ok=True)

    for rel in ACADEMIC_FILES:
        copy_file(rel)

    (ACADEMIC / "docs" / "ACADEMIC_SCOPE.md").write_text(
        "# R-SecOpsX Academic Edition\n\n"
        "This edition contains only PhD-safe, research-relevant, publication-safe modules.\n\n"
        "Enterprise-only modules such as advanced governance, secret blast-radius, AI agent internals, "
        "identity correlation, commercial license/IP engines, and proprietary decision logic are excluded.\n",
        encoding="utf-8",
    )

    print("\nDONE")
    print(f"Academic edition created at: {ACADEMIC}")

if __name__ == "__main__":
    main()