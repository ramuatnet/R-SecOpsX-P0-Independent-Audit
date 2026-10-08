$ErrorActionPreference = "Stop"

$root = (Get-Location).Path
$source = Join-Path $root "scanner\llm_security.py"
$backupDir = Join-Path $root "backup"

if (-not (Test-Path $source)) {
    throw "Production source not found: $source"
}

New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backup = Join-Path $backupDir "llm_security.py.before_llm01_hardening_v6_$stamp.py"
Copy-Item $source $backup -Force
Write-Host "[PASS] Backup created: $backup"

$py = Get-Content $source -Raw

$scanMarker = 'def scan_llm_file(filepath: str, content: str) -> list[dict]:'

$helper = @'
def _llm01_detection_view(line: str) -> str:
    """Normalize only the LLM01 detection view; preserve original evidence."""
    import unicodedata as _unicodedata

    value = str(line or "")

    # Decode common source-level Unicode/hex escapes.
    def _decode_unicode(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    value = re.sub(r"\\u([0-9a-fA-F]{4})", _decode_unicode, value)
    value = re.sub(r"\\U([0-9a-fA-F]{8})", _decode_unicode, value)
    value = re.sub(r"\\x([0-9a-fA-F]{2})", _decode_unicode, value)

    # Remove zero-width / Unicode format characters used to disrupt matching.
    value = "".join(
        ch for ch in value
        if _unicodedata.category(ch) != "Cf"
    )

    # Reconstruct common fragmented prompt strings:
    # "ignore previous " + "instructions"
    value = re.sub(
        r'(["\'])\s*\+\s*(["\'])',
        " ",
        value,
    )

    # Normalize whitespace after reconstruction.
    value = re.sub(r"\s+", " ", value).strip()
    return value


LLM01_ADDITIONAL_PATTERNS = (
    # Direct / multilingual prompt injection examples.
    r"ignora\s+las\s+instrucciones\s+anteriores",
    r"revela\s+las\s+instrucciones\s+del\s+sistema",

    # English fragmented/normalized variants.
    r"ignore\s+previous\s+instructions",
    r"ignore\s+all\s+previous\s+instructions",
    r"disregard\s+previous\s+instructions",
)

'@

if (-not $py.Contains("def _llm01_detection_view(line: str) -> str:")) {
    if (-not $py.Contains($scanMarker)) {
        throw "scan_llm_file marker not found. No production source written."
    }
    $py = $py.Replace($scanMarker, $helper + $scanMarker)
    Write-Host "[PASS] LLM01 detection normalization helper inserted"
} else {
    Write-Host "[INFO] LLM01 detection normalization helper already present"
}

# Exact structure supplied from the current production source.
$lineAnchor = @'
            rule_id = rule["rule_id"]
            matched_pattern = None

            if rule_id in HYBRID_EXACT_RULES:
'@

$lineReplacement = @'
            rule_id = rule["rule_id"]
            matched_pattern = None
            detection_line = (
                _llm01_detection_view(line)
                if rule_id == "LLM01_PROMPT_INJECTION"
                else line
            )

            if rule_id in HYBRID_EXACT_RULES:
'@

if (-not $py.Contains($lineAnchor)) {
    throw "Current rule initialization boundary not found. No production source written."
}
$py = $py.Replace($lineAnchor, $lineReplacement)

# In the non-hybrid branch, use the normalized detection view for LLM01.
$combinedAnchor = @'
                combined = rule.get("_combined_pattern")
                matched = combined is not None and combined.search(line)

                if not matched:
'@

$combinedReplacement = @'
                combined = rule.get("_combined_pattern")
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

if (-not $py.Contains($combinedAnchor)) {
    throw "Current combined-pattern boundary not found. No production source written."
}
$py = $py.Replace($combinedAnchor, $combinedReplacement)

# Replace only the alias search in the non-hybrid branch. There are two
# identical-looking alias blocks; target the second occurrence.
$aliasAnchor = @'
                    for pattern in RULE_SPECIFICITY_ALIASES.get(
                        rule["vuln_type"], []
                    ):
                        if re.search(pattern, line, re.IGNORECASE):
                            matched_pattern = pattern
                            break

                    if matched_pattern is None:
                        continue
'@

$aliasReplacement = @'
                    for pattern in RULE_SPECIFICITY_ALIASES.get(
                        rule["vuln_type"], []
                    ):
                        if re.search(
                            pattern,
                            detection_line,
                            re.IGNORECASE,
                        ):
                            matched_pattern = pattern
                            break

                    if matched_pattern is None:
                        continue
'@

$occurrences = ([regex]::Matches($py, [regex]::Escape($aliasAnchor))).Count
if ($occurrences -lt 2) {
    throw "Expected two alias blocks but found $occurrences. No production source written."
}

$first = $py.IndexOf($aliasAnchor)
$second = $py.IndexOf($aliasAnchor, $first + $aliasAnchor.Length)
$py = $py.Substring(0, $second) + $aliasReplacement + $py.Substring($second + $aliasAnchor.Length)

# Verify the patch before writing.
$required = @(
    "def _llm01_detection_view(line: str) -> str:",
    "LLM01_ADDITIONAL_PATTERNS",
    'if rule_id == "LLM01_PROMPT_INJECTION"',
    "combined.search(detection_line)",
    "detection_line,"
)

foreach ($needle in $required) {
    if (-not $py.Contains($needle)) {
        throw "Post-patch verification failed: $needle. No production source written."
    }
}

Set-Content -Path $source -Value $py -Encoding UTF8

python -m py_compile $source
if ($LASTEXITCODE -ne 0) {
    Copy-Item $backup $source -Force
    throw "Production compilation failed. Source restored from backup."
}

Write-Host "[PASS] Production LLM01 hardening v6 applied: $source"
Write-Host "[PASS] Production compilation"
Write-Host ""
Write-Host "Run targeted tests:"
Write-Host '  python -m pytest .\tests\test_v11_llm01_hardening_v1.py -q'
Write-Host ""
Write-Host "Then full regression:"
Write-Host '  python -m pytest .\tests -q'
