$ErrorActionPreference = "Stop"

$root = (Get-Location).Path
$source = Join-Path $root "scanner\llm_security.py"
$backupDir = Join-Path $root "backup"

if (-not (Test-Path -LiteralPath $source)) {
    throw "Production source not found: $source"
}

New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backup = Join-Path $backupDir "llm_security.py.before_llm01_hardening_v8_$stamp.py"
Copy-Item -LiteralPath $source -Destination $backup -Force
Write-Host "[PASS] Backup created: $backup"

$py = Get-Content -LiteralPath $source -Raw

# Normalize line endings for deterministic text matching, then restore CRLF
# when writing. This avoids the repeated CRLF/LF boundary failures seen in
# v1-v7 patch scripts.
$py = $py -replace "`r`n", "`n"

$scanMarker = 'def scan_llm_file(filepath: str, content: str) -> list[dict]:'
if (-not $py.Contains($scanMarker)) {
    throw "scan_llm_file marker not found. No production source written."
}

$helperMarker = 'def _llm01_detection_view(line: str) -> str:'
if (-not $py.Contains($helperMarker)) {
    $helper = @'
def _llm01_detection_view(line: str) -> str:
    """Detection-only normalization for OWASP LLM01 prompt-injection variants."""
    import unicodedata as _unicodedata

    value = str(line or "")

    def _decode(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    # Decode common source-level Unicode/hex escapes used to disguise tokens.
    value = re.sub(r"\\u([0-9a-fA-F]{4})", _decode, value)
    value = re.sub(r"\\U([0-9a-fA-F]{8})", _decode, value)
    value = re.sub(r"\\x([0-9a-fA-F]{2})", _decode, value)

    # Remove Unicode format/control characters such as zero-width space.
    value = "".join(
        ch for ch in value
        if _unicodedata.category(ch) != "Cf"
    )

    # Collapse fragmented quoted prompt pieces such as:
    # "ignore previous " + "instructions"
    value = re.sub(r"""(["'])\s*\+\s*(["'])""", " ", value)

    value = re.sub(r"\s+", " ", value).strip()
    return value


LLM01_ADDITIONAL_PATTERNS = (
    r"ignore\s+previous\s+instructions",
    r"ignore\s+all\s+previous\s+instructions",
    r"disregard\s+previous\s+instructions",
    r"ignora\s+las\s+instrucciones\s+anteriores",
    r"revela\s+las\s+instrucciones\s+del\s+sistema",
)

'@
    $py = $py.Replace($scanMarker, $helper + $scanMarker)
    Write-Host "[PASS] Detection helper inserted"
} else {
    Write-Host "[PASS] Detection helper already present"
}

# Insert detection_line immediately after the unique rule_id assignment.
# Regex is used instead of exact newline matching.
if (-not $py.Contains("detection_line = (")) {
    $pattern = '(?m)^(?<indent>\s*)rule_id = rule\["rule_id"\]\n(?<indent2>\s*)matched_pattern = None$'
    $replacement = '${indent}rule_id = rule["rule_id"]' + "`n" +
                   '${indent2}matched_pattern = None' + "`n" +
                   '${indent2}detection_line = (' + "`n" +
                   '${indent2}    _llm01_detection_view(line)' + "`n" +
                   '${indent2}    if rule_id == "LLM01_PROMPT_INJECTION"' + "`n" +
                   '${indent2}    else line' + "`n" +
                   '${indent2})'

    $newPy = [regex]::Replace($py, $pattern, $replacement, 1)
    if ($newPy -eq $py) {
        throw "rule_id/matched_pattern insertion boundary not found. No production source written."
    }
    $py = $newPy
    Write-Host "[PASS] LLM01 detection_line integration inserted"
} else {
    Write-Host "[PASS] LLM01 detection_line integration already present"
}

# Change only the generic combined-regex search from raw line to detection_line.
$rawSearch = 'combined.search(line)'
$normalizedSearch = 'combined.search(detection_line)'

if ($py.Contains($rawSearch) -and -not $py.Contains($normalizedSearch)) {
    $py = $py.Replace($rawSearch, $normalizedSearch)
    Write-Host "[PASS] Combined LLM01 matching redirected to detection_line"
} elseif ($py.Contains($normalizedSearch)) {
    Write-Host "[PASS] Combined LLM01 matching already uses detection_line"
} else {
    throw "Combined rule search expression not found. No production source written."
}

# Insert explicit LLM01 patterns after the generic combined match. Regex
# tolerates either LF/CRLF and blank-line differences.
if (-not $py.Contains("LLM01_ADDITIONAL_PATTERNS")) {
    throw "LLM01_ADDITIONAL_PATTERNS helper missing. No production source written."
}

if (-not $py.Contains('for pattern in LLM01_ADDITIONAL_PATTERNS:')) {
    $pattern = '(?ms)(^(?<indent>\s*)matched = combined is not None and combined\.search\(detection_line\)\n)(?<blank>\s*\n)(?<ifindent>\s*)if not matched:'
    $replacement = '${indent}matched = combined is not None and combined.search(detection_line)' + "`n`n" +
                   '${indent}if (' + "`n" +
                   '${indent}    not matched' + "`n" +
                   '${indent}    and rule_id == "LLM01_PROMPT_INJECTION"' + "`n" +
                   '${indent}):' + "`n" +
                   '${indent}    for pattern in LLM01_ADDITIONAL_PATTERNS:' + "`n" +
                   '${indent}        if re.search(pattern, detection_line, re.IGNORECASE):' + "`n" +
                   '${indent}            matched_pattern = pattern' + "`n" +
                   '${indent}            matched = True' + "`n" +
                   '${indent}            break' + "`n`n" +
                   '${ifindent}if not matched:'

    $newPy = [regex]::Replace($py, $pattern, $replacement, 1)
    if ($newPy -eq $py) {
        throw "LLM01 explicit-pattern insertion boundary not found. No production source written."
    }
    $py = $newPy
    Write-Host "[PASS] LLM01 explicit normalized patterns integrated"
} else {
    Write-Host "[PASS] LLM01 explicit normalized patterns already integrated"
}

# Guard against duplicate helper/integration blocks.
$required = @(
    'def _llm01_detection_view(line: str) -> str:',
    'LLM01_ADDITIONAL_PATTERNS = (',
    'detection_line = (',
    'combined.search(detection_line)',
    'for pattern in LLM01_ADDITIONAL_PATTERNS:'
)

foreach ($needle in $required) {
    if (-not $py.Contains($needle)) {
        throw "Verification failed: $needle. No production source written."
    }
}

# Compile a temporary candidate before replacing production source.
$temp = Join-Path $env:TEMP "rsecopsx_v11_llm01_hardening_v8_candidate.py"
[IO.File]::WriteAllText($temp, $py, (New-Object Text.UTF8Encoding($false)))

python -m py_compile $temp
if ($LASTEXITCODE -ne 0) {
    Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
    throw "Candidate production compilation failed. Existing production source was not changed."
}

# Commit only after candidate compilation succeeds.
$pyOut = $py -replace "`n", "`r`n"
[IO.File]::WriteAllText($source, $pyOut, (New-Object Text.UTF8Encoding($false)))
Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue

Write-Host "[PASS] Production LLM01 hardening v8 applied: $source"
Write-Host "[PASS] Existing production backup retained: $backup"
Write-Host "[PASS] Candidate compilation"
Write-Host ""
Write-Host "Run targeted tests:"
Write-Host '  python -m pytest .\tests\test_v11_llm01_hardening_v1.py -q'
Write-Host ""
Write-Host "Then full regression:"
Write-Host '  python -m pytest .\tests -q'
