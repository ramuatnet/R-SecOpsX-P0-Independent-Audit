$ErrorActionPreference = "Stop"

$root = (Get-Location).Path
$source = Join-Path $root "scanner\llm_security.py"
$backupDir = Join-Path $root "backup"

if (-not (Test-Path $source)) { throw "Production source not found: $source" }

New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backup = Join-Path $backupDir "llm_security.py.before_llm01_hardening_v7_$stamp.py"
Copy-Item $source $backup -Force
Write-Host "[PASS] Backup created: $backup"

$py = Get-Content $source -Raw

# Add the detection helper immediately before scan_llm_file, using the function
# definition as the only stable anchor.
$marker = 'def scan_llm_file(filepath: str, content: str) -> list[dict]:'
if (-not $py.Contains($marker)) { throw "scan_llm_file marker not found. No production source written." }

$helper = @'
def _llm01_detection_view(line: str) -> str:
    """Detection-only normalization; original source remains unchanged."""
    import unicodedata as _unicodedata

    value = str(line or "")

    def _decode(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    value = re.sub(r"\\u([0-9a-fA-F]{4})", _decode, value)
    value = re.sub(r"\\U([0-9a-fA-F]{8})", _decode, value)
    value = re.sub(r"\\x([0-9a-fA-F]{2})", _decode, value)

    value = "".join(
        ch for ch in value
        if _unicodedata.category(ch) != "Cf"
    )

    # Rejoin adjacent quoted fragments used to split prompt payloads.
    value = re.sub(r'(["''])\s*\+\s*(["''])', " ", value)
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

if (-not $py.Contains("def _llm01_detection_view(line: str) -> str:")) {
    $py = $py.Replace($marker, $helper + $marker)
    Write-Host "[PASS] Detection helper inserted"
}

# Rather than matching the surrounding rule block, insert a single
# detection_line assignment immediately after the rule_id assignment.
# This anchor is unique and is present in the supplied current source.
$anchor = '            rule_id = rule["rule_id"]' + "`r`n" + '            matched_pattern = None'
if (-not $py.Contains($anchor)) {
    $anchor = '            rule_id = rule["rule_id"]' + "`n" + '            matched_pattern = None'
}
if (-not $py.Contains($anchor)) {
    throw "rule_id/matched_pattern anchor not found. No production source written."
}

$replacement = @'
            rule_id = rule["rule_id"]
            matched_pattern = None
            detection_line = (
                _llm01_detection_view(line)
                if rule_id == "LLM01_PROMPT_INJECTION"
                else line
            )
'@

$py = $py.Replace($anchor, $replacement.TrimEnd())

# Change only the generic combined match expression. This is the exact
# expression visible in the current source supplied by the user.
$old = '                matched = combined is not None and combined.search(line)'
$new = '                matched = combined is not None and combined.search(detection_line)'

if (-not $py.Contains($old)) {
    throw "combined search expression not found. No production source written."
}
$py = $py.Replace($old, $new)

# Add explicit normalized LLM01 patterns immediately after the combined match.
$old2 = @'
                matched = combined is not None and combined.search(detection_line)

                if not matched:
'@
$new2 = @'
                matched = combined is not None and combined.search(detection_line)

                if (
                    not matched
                    and rule_id == "LLM01_PROMPT_INJECTION"
                ):
                    for pattern in LLM01_ADDITIONAL_PATTERNS:
                        if re.search(
                            pattern,
                            detection_line,
                            re.IGNORECASE,
                        ):
                            matched_pattern = pattern
                            matched = True
                            break

                if not matched:
'@
if (-not $py.Contains($old2)) {
    throw "LLM01 insertion point not found. No production source written."
}
$py = $py.Replace($old2, $new2)

# Ensure the helper and integration are present.
foreach ($needle in @(
    "def _llm01_detection_view(line: str) -> str:",
    "LLM01_ADDITIONAL_PATTERNS",
    "detection_line = (",
    "combined.search(detection_line)"
)) {
    if (-not $py.Contains($needle)) {
        throw "Verification failed: $needle. No production source written."
    }
}

Set-Content -Path $source -Value $py -Encoding UTF8

python -m py_compile $source
if ($LASTEXITCODE -ne 0) {
    Copy-Item $backup $source -Force
    throw "Production compilation failed. Source restored from backup."
}

Write-Host "[PASS] Production LLM01 hardening v7 applied: $source"
Write-Host "[PASS] Production compilation"
Write-Host ""
Write-Host "Run targeted tests:"
Write-Host '  python -m pytest .\tests\test_v11_llm01_hardening_v1.py -q'
Write-Host ""
Write-Host "Then full regression:"
Write-Host '  python -m pytest .\tests -q'
