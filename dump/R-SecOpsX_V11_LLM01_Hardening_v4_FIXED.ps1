$ErrorActionPreference = "Stop"

$root = (Get-Location).Path
$source = Join-Path $root "scanner\llm_security.py"
$backupDir = Join-Path $root "backup"

if (-not (Test-Path $source)) {
    throw "Production source not found: $source"
}

New-Item -ItemType Directory -Force -Path $backupDir | Out-Null

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backup = Join-Path $backupDir "llm_security.py.before_llm01_hardening_v4_$stamp.py"
Copy-Item $source $backup -Force
Write-Host "[PASS] Backup created: $backup"

$py = Get-Content $source -Raw

$marker = '    for lineno, line in enumerate(lines, start=1):'
if (-not $py.Contains($marker)) {
    throw "Expected scan_llm_file line-processing boundary not found. No production source written."
}

# Insert small, isolated normalization helpers immediately before scan_llm_file.
# Existing source/evidence remains untouched; only the LLM01 matching view is normalized.
$helperMarker = 'def scan_llm_file(filepath: str, content: str) -> list[dict]:'

if (-not $py.Contains($helperMarker)) {
    throw "scan_llm_file definition not found. No production source written."
}

$helper = @'
def _llm01_detection_view(line: str) -> str:
    """Build a conservative detection-only view for LLM01 prompt injection."""
    import re as _re

    value = str(line or "")

    # Decode common escaped Unicode/hex forms without altering the original
    # source used later for evidence/reporting.
    def _u4(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    def _u8(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    def _xh(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    value = _re.sub(r"\\u([0-9a-fA-F]{4})", _u4, value)
    value = _re.sub(r"\\U([0-9a-fA-F]{8})", _u8, value)
    value = _re.sub(r"\\x([0-9a-fA-F]{2})", _xh, value)

    # Remove Unicode format/zero-width disruption characters.
    value = "".join(
        ch for ch in value
        if ch not in "\u200b\u200c\u200d\u2060\ufeff"
    )

    # Conservative source-level reconstruction for simple fragmented
    # string payloads such as:
    # "ignore previous " + "instructions"
    value = _re.sub(
        r'(["\'])\s*\+\s*(["\'])',
        " ",
        value,
    )

    # Collapse punctuation/whitespace introduced by fragmentation.
    value = _re.sub(r'[\r\n\t]+', ' ', value)
    value = _re.sub(r'\s{2,}', ' ', value)

    return value


LLM01_ADDITIONAL_PATTERNS = [
    # Spanish examples represented in the behavioral corpus.
    r"ignora\s+las\s+instrucciones\s+anteriores",
    r"revela\s+las\s+instrucciones\s+del\s+sistema",
]

'@

if (-not $py.Contains("def _llm01_detection_view(line: str) -> str:")) {
    $py = $py.Replace($helperMarker, $helper + $helperMarker)
}

# Make the existing loop use a detection-only view for LLM01 while preserving
# the original line for finding evidence and deduplication.
$old = @'
        for rule in LLM_RULES:
            rule_id = rule["rule_id"]
            matched_pattern = None

            if rule_id in HYBRID_EXACT_RULES:
'@

$new = @'
        for rule in LLM_RULES:
            rule_id = rule["rule_id"]
            matched_pattern = None

            detection_line = (
                _llm01_detection_view(line)
                if rule_id == "LLM01_PROMPT_INJECTION"
                else line
            )

            if rule_id in HYBRID_EXACT_RULES:
'@

if (-not $py.Contains($old)) {
    throw "Expected rule-loop boundary not found. No production source written."
}
$py = $py.Replace($old, $new)

# Replace only the two LLM01-relevant re.search sites inside the rule loop.
# The replacements are intentionally constrained to the exact strings.
$py = $py.Replace(
    'if re.search(pattern, line, re.IGNORECASE):',
    'if re.search(pattern, detection_line, re.IGNORECASE):'
)

$py = $py.Replace(
    'if re.search(pattern, line, re.IGNORECASE):',
    'if re.search(pattern, detection_line, re.IGNORECASE):'
)

# Add multilingual aliases after existing RULE_SPECIFICITY_ALIASES is available.
$aliasMarker = '    for lineno, line in enumerate(lines, start=1):'
$aliasBlock = @'
    llm01_extra_patterns = LLM01_ADDITIONAL_PATTERNS

'@
if (-not $py.Contains("    llm01_extra_patterns = LLM01_ADDITIONAL_PATTERNS")) {
    $py = $py.Replace($aliasMarker, $aliasBlock + $aliasMarker)
}

# Insert an explicit LLM01 fallback immediately after the normal combined-pattern
# test, before the existing "if not matched" branch.
$combinedBlock = @'
                combined = rule.get("_combined_pattern")
                matched = combined is not None and combined.search(line)

                if not matched:
'@

$combinedReplacement = @'
                combined = rule.get("_combined_pattern")
                matched = (
                    combined is not None
                    and combined.search(detection_line)
                )

                if (
                    not matched
                    and rule_id == "LLM01_PROMPT_INJECTION"
                ):
                    for pattern in llm01_extra_patterns:
                        if re.search(pattern, detection_line, re.IGNORECASE):
                            matched_pattern = pattern
                            matched = True
                            break

                if not matched:
'@

if (-not $py.Contains($combinedBlock)) {
    throw "Expected combined-pattern boundary not found. No production source written."
}
$py = $py.Replace($combinedBlock, $combinedReplacement)

Set-Content -Path $source -Value $py -Encoding UTF8

python -m py_compile $source
if ($LASTEXITCODE -ne 0) {
    Copy-Item $backup $source -Force
    throw "Production compilation failed. Source restored from backup."
}

Write-Host "[PASS] Production LLM01 hardening v4 applied: $source"
Write-Host "[PASS] Production compilation"
Write-Host ""
Write-Host "Run next:"
Write-Host '  python -m pytest .\tests\test_v11_llm01_hardening_v1.py -q'
Write-Host '  python -m pytest .\tests -q'
