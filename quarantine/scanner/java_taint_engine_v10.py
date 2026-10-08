"""
R-SecOpsX V10
Fresh isolated Java taint/security analysis engine.

Purpose:
    Independent replacement candidate for the legacy Java pipeline.

Design:
    J2   -> weak crypto / weak random
    J3   -> direct source-to-sink propagation
    J3.2 -> variable/interprocedural propagation
    J32C -> collection/string propagation
    J4   -> additional Java security semantics
    R13  -> candidate enrichment

This module intentionally has NO dependency on scanner.taint_engine.
"""

from __future__ import annotations

from pathlib import Path
import re


# ============================================================
# Common helpers
# ============================================================

def _finding(
    *,
    filepath: str,
    line: int,
    vuln_type: str,
    rule_id: str,
    title: str,
    severity: str = "HIGH",
    source: str | None = None,
    sink: str | None = None,
    evidence: str | None = None,
    layer: str | None = None,
) -> dict:
    return {
        "file": str(filepath),
        "line": int(line),
        "vuln_type": vuln_type,
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "source": source,
        "sink": sink,
        "evidence": evidence,
        "layer": layer,
    }


def _lines(source: str):
    return source.splitlines()


def _line_number(lines, index):
    return index + 1


def _dedupe(findings: list[dict]) -> list[dict]:
    result = []
    seen = set()

    for f in findings:
        key = (
            f.get("rule_id"),
            f.get("file"),
            f.get("line"),
            f.get("vuln_type"),
        )

        if key not in seen:
            seen.add(key)
            result.append(f)

    return result


# ============================================================
# J2 - Weak cryptography / weak randomness
# ============================================================

def scan_j2(filepath: str, source: str) -> list[dict]:
    findings = []
    lines = _lines(source)

    for i, line in enumerate(lines):

        if re.search(
            r'MessageDigest\s*\.\s*getInstance\s*\(\s*["\'](?:MD5|SHA-1)["\']',
            line,
            re.I,
        ):
            algorithm = re.search(
                r'getInstance\s*\(\s*["\']([^"\']+)["\']',
                line,
                re.I,
            )

            value = algorithm.group(1) if algorithm else "weak hash"

            findings.append(
                _finding(
                    filepath=filepath,
                    line=i + 1,
                    vuln_type="weak_hash",
                    rule_id="JAVA_J2_WEAK_HASH",
                    title="Java weak cryptographic hash",
                    severity="HIGH",
                    evidence=line.strip(),
                    layer="J2",
                )
            )

        if re.search(
            r'\bnew\s+Random\s*\(',
            line,
            re.I,
        ):
            findings.append(
                _finding(
                    filepath=filepath,
                    line=i + 1,
                    vuln_type="weak_random",
                    rule_id="JAVA_J2_WEAK_RANDOM",
                    title="Java insecure random generator",
                    severity="MEDIUM",
                    evidence=line.strip(),
                    layer="J2",
                )
            )

    return findings


# ============================================================
# Source identification
# ============================================================

_SOURCE_PATTERNS = (
    r'\brequest\.getParameter\s*\(',
    r'\brequest\.getHeader\s*\(',
    r'\brequest\.getQueryString\s*\(',
    r'\buserInput\b',
    r'\binput\b',
    r'\bparam\b',
    r'\bparameter\b',
)


def _is_source_expression(expr: str) -> bool:
    return any(re.search(p, expr, re.I) for p in _SOURCE_PATTERNS)


# ============================================================
# J3 - Direct source -> sink
# ============================================================

def scan_j3(filepath: str, source: str) -> list[dict]:
    findings = []
    lines = _lines(source)

    tainted = set()

    assignment_re = re.compile(
        r'\b(?:String|Object|var)?\s*'
        r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+);'
    )

    for i, line in enumerate(lines):
        stripped = line.strip()

        m = assignment_re.search(stripped)

        if m:
            variable = m.group(1)
            expression = m.group(2)

            if _is_source_expression(expression):
                tainted.add(variable)

            elif any(
                re.search(rf'\b{re.escape(v)}\b', expression)
                for v in tainted
            ):
                tainted.add(variable)

        # SQL sink
        if re.search(
            r'\b(?:executeQuery|executeUpdate|execute)\s*\(',
            stripped,
            re.I,
        ):
            if _is_source_expression(stripped) or any(
                re.search(rf'\b{re.escape(v)}\b', stripped)
                for v in tainted
            ):
                findings.append(
                    _finding(
                        filepath=filepath,
                        line=i + 1,
                        vuln_type="sql_injection",
                        rule_id="JAVA_J3_SQL_INJECTION",
                        title="Potential SQL injection",
                        severity="HIGH",
                        source="user-controlled input",
                        sink=stripped[:160],
                        evidence=stripped,
                        layer="J3",
                    )
                )

        # Command execution
        if re.search(
            r'Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.exec\s*\(',
            stripped,
            re.I,
        ):
            if _is_source_expression(stripped) or any(
                re.search(rf'\b{re.escape(v)}\b', stripped)
                for v in tainted
            ):
                findings.append(
                    _finding(
                        filepath=filepath,
                        line=i + 1,
                        vuln_type="command_injection",
                        rule_id="JAVA_J3_COMMAND_INJECTION",
                        title="Potential command injection",
                        severity="CRITICAL",
                        source="user-controlled input",
                        sink="Runtime.getRuntime().exec",
                        evidence=stripped,
                        layer="J3",
                    )
                )

    return findings


# ============================================================
# J3.2 - broader variable / method propagation
# ============================================================

def scan_j32(filepath: str, source: str) -> list[dict]:
    findings = []
    lines = _lines(source)

    tainted = set()

    for i, line in enumerate(lines):
        stripped = line.strip()

        # x = userInput
        m = re.search(
            r'\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);',
            stripped,
        )

        if m:
            target = m.group(1)
            expr = m.group(2)

            if _is_source_expression(expr) or any(
                re.search(rf'\b{re.escape(v)}\b', expr)
                for v in tainted
            ):
                tainted.add(target)

        # Method argument propagation
        if re.search(
            r'\b(?:executeQuery|executeUpdate|execute)\s*\(',
            stripped,
            re.I,
        ):
            if any(
                re.search(rf'\b{re.escape(v)}\b', stripped)
                for v in tainted
            ):
                findings.append(
                    _finding(
                        filepath=filepath,
                        line=i + 1,
                        vuln_type="tainted_sql_argument",
                        rule_id="JAVA_J32_INTERPROC_SQL",
                        title="Tainted value propagated to SQL sink",
                        severity="HIGH",
                        sink=stripped[:160],
                        evidence=stripped,
                        layer="J3.2",
                    )
                )

        if re.search(
            r'Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.exec\s*\(',
            stripped,
            re.I,
        ):
            if any(
                re.search(rf'\b{re.escape(v)}\b', stripped)
                for v in tainted
            ):
                findings.append(
                    _finding(
                        filepath=filepath,
                        line=i + 1,
                        vuln_type="tainted_command_argument",
                        rule_id="JAVA_J32_INTERPROC_COMMAND",
                        title="Tainted value propagated to command sink",
                        severity="CRITICAL",
                        sink="Runtime.getRuntime().exec",
                        evidence=stripped,
                        layer="J3.2",
                    )
                )

    return findings


# ============================================================
# J32C - collection / string propagation
# ============================================================

def scan_j32c(filepath: str, source: str) -> list[dict]:
    """
    J32C - collection/string taint propagation.

    Contract:
      1. A collection becomes tainted only when a tainted value is added.
      2. A value read from a tainted collection becomes tainted.
      3. Taint propagates through subsequent collection additions.
      4. Explicit reassignment to a clean/constant value removes taint
         from the target variable.
      5. A command sink is reported only when its actual argument is
         currently tainted.
    """
    findings = []
    lines = _lines(source)

    # ------------------------------------------------------------
    # J32C DOMAIN SEPARATION
    # ------------------------------------------------------------
    #
    # J32C must NOT consume the generic J3/J3.2 taint domain.
    #
    # Generic taint:
    #     userInput -> sink
    #
    # J32C taint:
    #     tainted source -> collection.add(...)
    #                    -> collection.get(...)
    #                    -> derived value -> sink
    #
    # Therefore J32C maintains its own state.
    # ------------------------------------------------------------

    # Collections currently known to contain collection-derived taint.
    tainted_collections = set()

    # Variables currently known to be collection-derived taint.
    collection_derived_values = set()

    def is_collection_derived(value: str) -> bool:
        return any(
            re.search(rf"\b{re.escape(name)}\b", value)
            for name in collection_derived_values
        )

    def is_taint_source_for_collection(value: str) -> bool:
        # Direct source entering a collection is a valid J32C origin.
        if re.search(r"\buserInput\b", value):
            return True

        # A value already derived through the J32C domain may
        # subsequently enter another collection.
        return is_collection_derived(value)

    method_depth = 0

    for i, line in enumerate(lines):
        stripped = line.strip()

        # --------------------------------------------------------
        # Java method boundary.
        #
        # J32C state is method-local. Taint from one method must
        # never leak into another method in the same source file.
        # --------------------------------------------------------
        method_signature = re.search(
            r'\b(?:public|private|protected)?\s*'
            r'(?:static\s+)?'
            r'[A-Za-z_$][A-Za-z0-9_$<>\[\],.? ]*\s+'
            r'[A-Za-z_$][A-Za-z0-9_$]*\s*\([^;{}]*\)\s*'
            r'(?:throws\s+[^{]+)?\s*\{',
            stripped,
        )

        if method_signature:
            tainted_collections.clear()
            collection_derived_values.clear()
            method_depth = 1
            continue

        # --------------------------------------------------------
        # Collection insertion:
        #
        # values.add(userInput)
        # values.add(taintedVariable)
        # --------------------------------------------------------
        m = re.search(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\.add\s*\(\s*(.*?)\s*\)",
            stripped,
        )

        if m:
            collection = m.group(1)
            value = m.group(2)

            if is_taint_source_for_collection(value):
                tainted_collections.add(collection)

        # --------------------------------------------------------
        # Collection extraction:
        #
        # String collected = values.get(0)
        # var collected = values.get(0)
        #
        # The target state is explicitly replaced.
        # --------------------------------------------------------
        m = re.search(
            r"\b(?:String|var)\s+"
            r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
            r"([A-Za-z_][A-Za-z0-9_]*)\.get\s*\(",
            stripped,
        )

        if m:
            target = m.group(1)
            collection = m.group(2)

            if collection in tainted_collections:
                collection_derived_values.add(target)
            else:
                # Important: clean collection read clears only the
                # J32C collection-derived state.
                collection_derived_values.discard(target)

        else:
            # ----------------------------------------------------
            # Ordinary assignment / reassignment:
            #
            # collected = "safe";
            # String collected = "safe";
            # x = taintedValue;
            #
            # A clean RHS explicitly removes previous taint.
            # ----------------------------------------------------
            m = re.search(
                r"(?:\b(?:String|var)\s+)?"
                r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*;",
                stripped,
            )

            if m:
                target = m.group(1)
                rhs = m.group(2)

                if is_collection_derived(rhs):
                    collection_derived_values.add(target)
                else:
                    collection_derived_values.discard(target)

        # --------------------------------------------------------
        # Runtime command sink.
        #
        # Report only when the actual sink argument is currently
        # tainted. This prevents stale-variable false positives.
        # --------------------------------------------------------
        m = re.search(
            r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.exec\s*\(\s*(.*?)\s*\)",
            stripped,
            re.I,
        )

        if m:
            argument = m.group(1)

            if is_collection_derived(argument):
                findings.append(
                    _finding(
                        filepath=filepath,
                        line=i + 1,
                        vuln_type="collection_command_injection",
                        rule_id="JAVA_J32C_COLLECTION_COMMAND",
                        title="Collection-derived tainted value reaches command sink",
                        severity="CRITICAL",
                        source="collection-derived input",
                        sink="Runtime.getRuntime().exec",
                        evidence=stripped,
                        layer="J32C",
                    )
                )

    return findings


# ============================================================
# J4 - Java security semantics
# ============================================================

def scan_j4(filepath: str, source: str) -> list[dict]:
    findings = []
    lines = _lines(source)

    for i, line in enumerate(lines):
        stripped = line.strip()

        if re.search(
            r'\bStatement\s+\w+\s*=.*createStatement\s*\(',
            stripped,
            re.I,
        ):
            findings.append(
                _finding(
                    filepath=filepath,
                    line=i + 1,
                    vuln_type="dynamic_sql_statement",
                    rule_id="JAVA_J4_DYNAMIC_STATEMENT",
                    title="Dynamic SQL Statement construction",
                    severity="MEDIUM",
                    evidence=stripped,
                    layer="J4",
                )
            )

        runtime_match = re.search(
            r'\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.exec\s*\((.*)\)',
            stripped,
            re.I,
        )

        if runtime_match:
            argument = runtime_match.group(1).strip()

            # Constant-only command arguments are not treated as
            # dynamic/tainted execution by the J4 semantic contract.
            is_constant = bool(
                re.fullmatch(
                    r'"(?:\\.|[^"\\])*"',
                    argument,
                    re.S,
                )
            )

            if not is_constant:
                findings.append(
                    _finding(
                        filepath=filepath,
                        line=i + 1,
                        vuln_type="runtime_command_execution",
                        rule_id="JAVA_J4_RUNTIME_EXEC",
                        title="Runtime command execution",
                        severity="HIGH",
                        evidence=stripped,
                        layer="J4",
                    )
                )

    return findings


# ============================================================
# R13 / V2R12 candidate enrichment
# ============================================================

def scan_r13(filepath: str, source: str) -> list[dict]:
    """
    Conservative R13/V2R12 layer.

    This is intentionally independent from the historical R13 candidate
    files. It provides a stable integration point first.
    """

    findings = []
    lines = _lines(source)

    for i, line in enumerate(lines):
        stripped = line.strip()

        runtime_match = re.search(
            r'\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.exec\s*\((.*)\)',
            stripped,
            re.I,
        )

        process_match = re.search(
            r'\bProcessBuilder\s*\((.*)\)',
            stripped,
            re.I,
        )

        argument = None

        if runtime_match:
            argument = runtime_match.group(1).strip()
        elif process_match:
            argument = process_match.group(1).strip()

        if argument is not None:
            is_constant = bool(
                re.fullmatch(
                    r'"(?:\\.|[^"\\])*"',
                    argument,
                    re.S,
                )
            )

            if not is_constant:
                findings.append(
                    _finding(
                        filepath=filepath,
                        line=i + 1,
                        vuln_type="generic_command_sink",
                        rule_id="JAVA_R13_GENERIC_COMMAND_SINK",
                        title="Generic Java command execution sink",
                        severity="HIGH",
                        evidence=stripped,
                        layer="R13",
                    )
                )

    return findings


# ============================================================
# Canonical fresh pipeline
# ============================================================

def analyze_file(filepath: str) -> list[dict]:
    path = Path(filepath)
    source = path.read_text(
        encoding="utf-8",
        errors="replace",
    )

    findings = []

    findings.extend(scan_j2(filepath, source))
    findings.extend(scan_j3(filepath, source))
    findings.extend(scan_j32(filepath, source))
    findings.extend(scan_j32c(filepath, source))
    findings.extend(scan_j4(filepath, source))
    findings.extend(scan_r13(filepath, source))

    return _dedupe(findings)


def scan_file(filepath: str) -> list[dict]:
    return analyze_file(filepath)


__all__ = [
    "analyze_file",
    "scan_file",
    "scan_j2",
    "scan_j3",
    "scan_j32",
    "scan_j32c",
    "scan_j4",
    "scan_r13",
]
