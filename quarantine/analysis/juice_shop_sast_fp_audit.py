import csv
import json
from collections import Counter
from pathlib import Path


INPUT = Path(r"reports\clean_report.json")
OUTPUT_DIR = Path(r"reports\fp_audit")


def text(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def get(finding, *keys):
    for key in keys:
        if key in finding:
            return finding[key]
    return ""


def classify_path(path):
    p = path.replace("/", "\\").lower()

    if "node_modules" in p or "\\vendor\\" in p:
        return "THIRD_PARTY"

    if (
        "\\dist\\" in p
        or "\\build\\" in p
        or "\\coverage\\" in p
        or "\\out\\" in p
        or ".min.js" in p
        or ".bundle.js" in p
    ):
        return "GENERATED_BUILD"

    if (
        "bom.json" in p
        or "sbom" in p
        or "package-lock.json" in p
        or "yarn.lock" in p
        or "pnpm-lock.yaml" in p
    ):
        return "ARTIFACT_BOM"

    if (
        "\\test\\" in p
        or "\\tests\\" in p
        or "__tests__" in p
        or "\\fixtures\\" in p
        or "cypress" in p
    ):
        return "TEST_FIXTURE"

    if p.endswith(".d.ts"):
        return "TYPE_DEFINITION"

    return "FIRST_PARTY_OR_UNKNOWN"


def extract_paths(finding):
    paths = []

    for key in (
        "file",
        "filepath",
        "file_path",
        "path",
        "source_file",
        "location",
        "affected_files",
        "files",
    ):
        value = finding.get(key)

        if isinstance(value, str):
            paths.append(value)

        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    paths.append(item)
                elif isinstance(item, dict):
                    for k in ("file", "filepath", "file_path", "path", "location"):
                        if isinstance(item.get(k), str):
                            paths.append(item[k])

        elif isinstance(value, dict):
            for k in ("file", "filepath", "file_path", "path", "location"):
                if isinstance(value.get(k), str):
                    paths.append(value[k])

    # Preserve order and remove duplicates.
    return list(dict.fromkeys(p for p in paths if p))


def main():
    if not INPUT.exists():
        raise FileNotFoundError(f"Input not found: {INPUT}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Loading: {INPUT}")
    print(f"Size: {INPUT.stat().st_size / (1024 * 1024):.1f} MB")

    with INPUT.open("r", encoding="utf-8") as f:
        report = json.load(f)

    findings = report.get("findings")

    if not isinstance(findings, list):
        raise RuntimeError("report['findings'] is not a list")

    print(f"SAST findings in report: {len(findings):,}")

    severity = Counter()
    confidence = Counter()
    rules = Counter()
    cwes = Counter()
    engines = Counter()
    scopes = Counter()
    path_classes = Counter()
    llm_rules = Counter()

    rows = []

    for index, finding in enumerate(findings, 1):
        if not isinstance(finding, dict):
            continue

        title = text(get(finding, "title", "name", "finding", "category"))
        rule = text(get(finding, "rule_id", "rule", "check_id", "category"))
        sev = text(get(finding, "severity", "level")).upper() or "UNKNOWN"
        conf = text(get(finding, "confidence")).upper() or "UNKNOWN"
        cwe = text(get(finding, "cwe", "cwe_id")) or "UNKNOWN"
        engine = text(get(finding, "engine", "detector", "source")) or "UNKNOWN"

        paths = extract_paths(finding)
        classes = [classify_path(p) for p in paths]

        if not classes:
            scope = "NO_PATH"
            classes = ["NO_PATH"]
        elif "THIRD_PARTY" in classes:
            scope = "THIRD_PARTY_PRESENT"
        elif "GENERATED_BUILD" in classes:
            scope = "GENERATED_BUILD_PRESENT"
        elif "ARTIFACT_BOM" in classes:
            scope = "ARTIFACT_BOM_PRESENT"
        elif "TEST_FIXTURE" in classes:
            scope = "TEST_FIXTURE_PRESENT"
        elif "TYPE_DEFINITION" in classes:
            scope = "TYPE_DEFINITION_PRESENT"
        else:
            scope = "FIRST_PARTY_OR_UNKNOWN"

        # LLM rule identification based on the actual rule/title.
        combined = f"{title} {rule}".lower()
        llm = (
            "llm" in combined
            or "prompt" in combined
            or "chatbot" in combined
            or "model" in combined
        )

        severity[sev] += 1
        confidence[conf] += 1
        rules[rule] += 1
        cwes[cwe] += 1
        engines[engine] += 1
        scopes[scope] += 1

        for cls in set(classes):
            path_classes[cls] += 1

        if llm:
            llm_rules[rule] += 1

        rows.append(
            {
                "index": index,
                "finding_id": text(get(finding, "finding_id", "id", "uuid")),
                "title": title,
                "rule": rule,
                "severity": sev,
                "confidence": conf,
                "engine": engine,
                "cwe": cwe,
                "scope": scope,
                "path_classes": "; ".join(sorted(set(classes))),
                "path_count": len(paths),
                "sample_paths": " | ".join(paths[:10]),
                "llm_candidate": "YES" if llm else "NO",
            }
        )

    csv_path = OUTPUT_DIR / "sast_fp_audit.csv"

    with csv_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    summary = {
        "audit": "R-SecOpsX Juice Shop v20.2.0 SAST FP Audit",
        "input": str(INPUT),
        "sast_findings_audited": len(findings),
        "severity": severity,
        "confidence": confidence,
        "scope": scopes,
        "path_classes": path_classes,
        "top_rules": rules.most_common(50),
        "top_cwes": cwes.most_common(50),
        "top_engines": engines.most_common(30),
        "llm_rules": llm_rules.most_common(50),
    }

    # Counter is not JSON serializable.
    summary = json.loads(json.dumps(summary, default=dict))

    json_path = OUTPUT_DIR / "sast_fp_summary.json"
    json_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    md_path = OUTPUT_DIR / "sast_fp_summary.md"

    lines = [
        "# R-SecOpsX — Juice Shop v20.2.0 SAST FP Audit",
        "",
        f"- SAST findings audited: **{len(findings):,}**",
        "",
        "## Scope",
    ]

    for key, value in scopes.most_common():
        lines.append(f"- {key}: **{value:,}**")

    lines.extend(["", "## Path Classes"])

    for key, value in path_classes.most_common():
        lines.append(f"- {key}: **{value:,}**")

    lines.extend(["", "## Severity"])

    for key, value in severity.most_common():
        lines.append(f"- {key}: **{value:,}**")

    lines.extend(["", "## Confidence"])

    for key, value in confidence.most_common():
        lines.append(f"- {key}: **{value:,}**")

    lines.extend(["", "## Top Rules"])

    for key, value in rules.most_common(30):
        lines.append(f"- `{key}`: **{value:,}**")

    lines.extend(["", "## LLM Candidate Rules"])

    for key, value in llm_rules.most_common(30):
        lines.append(f"- `{key}`: **{value:,}**")

    lines.extend(
        [
            "",
            "> This is a triage audit, not a ground-truth precision/recall calculation.",
            "> The original clean_report.json is not modified.",
        ]
    )

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print()
    print("AUDIT COMPLETE")
    print(f"SAST findings audited : {len(findings):,}")
    print(f"CSV                   : {csv_path}")
    print(f"JSON                  : {json_path}")
    print(f"Markdown              : {md_path}")

    print()
    print("SCOPE:")
    for key, value in scopes.most_common():
        print(f"  {key:28} {value:,}")

    print()
    print("PATH CLASSES:")
    for key, value in path_classes.most_common():
        print(f"  {key:28} {value:,}")

    print()
    print("TOP LLM RULES:")
    for key, value in llm_rules.most_common(15):
        print(f"  {key:45} {value:,}")


if __name__ == "__main__":
    main()