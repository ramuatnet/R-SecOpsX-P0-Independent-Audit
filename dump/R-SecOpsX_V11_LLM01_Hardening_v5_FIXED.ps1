$ErrorActionPreference="Stop"
$root=(Get-Location).Path
$source=Join-Path $root "scanner\llm_security.py"
$backupDir=Join-Path $root "backup"
if(-not(Test-Path $source)){throw "Production source not found: $source"}
New-Item -ItemType Directory -Force -Path $backupDir|Out-Null
$stamp=Get-Date -Format "yyyyMMdd-HHmmss"
$backup=Join-Path $backupDir "llm_security.py.before_llm01_hardening_v5_$stamp.py"
Copy-Item $source $backup -Force
Write-Host "[PASS] Backup created: $backup"
$py=Get-Content $source -Raw
$scanMarker='def scan_llm_file(filepath: str, content: str) -> list[dict]:'
if(-not $py.Contains($scanMarker)){throw "scan_llm_file definition not found. No production source written."}

$helper=@'
def _llm01_detection_view(line: str) -> str:
    """Conservative detection-only normalization for LLM01."""
    import re as _re
    import unicodedata as _unicodedata
    value=str(line or "")
    def _decode(match):
        try:
            return chr(int(match.group(1),16))
        except ValueError:
            return match.group(0)
    value=_re.sub(r"\\u([0-9a-fA-F]{4})",_decode,value)
    value=_re.sub(r"\\U([0-9a-fA-F]{8})",_decode,value)
    value=_re.sub(r"\\x([0-9a-fA-F]{2})",_decode,value)
    value="".join(ch for ch in value if _unicodedata.category(ch)!="Cf")
    value=_re.sub(r'(["\'])\s*\+\s*(["\'])'," ",value)
    value=_re.sub(r"\s+"," ",value).strip()
    return value

LLM01_ADDITIONAL_PATTERNS = [
    r"ignora\s+las\s+instrucciones\s+anteriores",
    r"revela\s+las\s+instrucciones\s+del\s+sistema",
]

'@
if(-not $py.Contains("def _llm01_detection_view(line: str) -> str:")){
    $py=$py.Replace($scanMarker,$helper+$scanMarker)
    Write-Host "[PASS] LLM01 detection normalization helper inserted"
}

$loopMarker=@'
    for lineno, line in enumerate(lines, start=1):

        line_matches = []

        for rule in LLM_RULES:
            rule_id = rule["rule_id"]
            matched_pattern = None

'@
$loopReplacement=@'
    for lineno, line in enumerate(lines, start=1):

        line_matches = []

        for rule in LLM_RULES:
            rule_id = rule["rule_id"]
            matched_pattern = None
            detection_line = (
                _llm01_detection_view(line)
                if rule_id == "LLM01_PROMPT_INJECTION"
                else line
            )

'@
if(-not $py.Contains($loopMarker)){throw "Current V11 rule-loop boundary not found. No production source written."}
$py=$py.Replace($loopMarker,$loopReplacement)

$combinedOld=@'
                combined = rule.get("_combined_pattern")
                matched = combined is not None and combined.search(line)

                if not matched:
'@
$combinedNew=@'
                combined = rule.get("_combined_pattern")
                matched = (
                    combined is not None
                    and combined.search(detection_line)
                )

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
if(-not $py.Contains($combinedOld)){throw "Current V11 combined-pattern boundary not found. No production source written."}
$py=$py.Replace($combinedOld,$combinedNew)

$aliasOld=@'
                    for pattern in RULE_SPECIFICITY_ALIASES.get(
                        rule["vuln_type"], []
                    ):
                        if re.search(pattern, line, re.IGNORECASE):
'@
$aliasNew=@'
                    for pattern in RULE_SPECIFICITY_ALIASES.get(
                        rule["vuln_type"], []
                    ):
                        if re.search(
                            pattern,
                            detection_line,
                            re.IGNORECASE,
                        ):
'@
$first=$py.IndexOf($aliasOld)
$second=$py.IndexOf($aliasOld,$first+$aliasOld.Length)
if($first -lt 0 -or $second -lt 0){throw "Expected second alias block not found. No production source written."}
$py=$py.Substring(0,$second)+$aliasNew+$py.Substring($second+$aliasOld.Length)

foreach($needle in @("def _llm01_detection_view(line: str) -> str:","detection_line = (","combined.search(detection_line)","LLM01_ADDITIONAL_PATTERNS")){if(-not $py.Contains($needle)){throw "Post-patch verification failed: $needle"}}

Set-Content -Path $source -Value $py -Encoding UTF8
python -m py_compile $source
if($LASTEXITCODE -ne 0){Copy-Item $backup $source -Force;throw "Production compilation failed. Source restored from backup."}
Write-Host "[PASS] Production LLM01 hardening v5 applied: $source"
Write-Host "[PASS] Production compilation"
Write-Host "Next: python -m pytest .\tests\test_v11_llm01_hardening_v1.py -q"
Write-Host "Then: python -m pytest .\tests -q"
