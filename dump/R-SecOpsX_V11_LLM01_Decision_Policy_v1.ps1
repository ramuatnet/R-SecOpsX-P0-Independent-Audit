$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Scanner = Join-Path $Root 'scanner\llm_security.py'
$FindingModel = Join-Path $Root 'core\finding_model.py'
$Tests = Join-Path $Root 'tests'
$Backup = Join-Path $Root 'backup'
New-Item -ItemType Directory -Force -Path $Tests,$Backup | Out-Null

function Backup-File($Path,$Tag) {
    if (!(Test-Path -LiteralPath $Path)) { throw "Production file not found: $Path" }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $dest = Join-Path $Backup ((Split-Path $Path -Leaf) + '.before_' + $Tag + '_' + $stamp)
    Copy-Item -LiteralPath $Path -Destination $dest -Force
    Write-Host "[PASS] Backup: $dest"
    return $dest
}

$scannerBackup = Backup-File $Scanner 'llm01_decision_policy_v1'
$findingBackup = Backup-File $FindingModel 'llm01_decision_policy_v1'
$testSource = Join-Path $PSScriptRoot 'test_v11_llm01_decision_policy_v1.py'
$testPath = Join-Path $Tests 'test_v11_llm01_decision_policy_v1.py'
if (!(Test-Path -LiteralPath $testSource)) { throw "Bundled acceptance test missing: $testSource" }
Copy-Item -LiteralPath $testSource -Destination $testPath -Force
Write-Host "[PASS] Acceptance test installed: $testPath"

try {
    $py = [IO.File]::ReadAllText($Scanner,(New-Object Text.UTF8Encoding($false)))
    $marker = 'def scan_llm_file(filepath: str, content: str) -> list[dict]:'
    if (!$py.Contains($marker)) { throw 'Required scanner anchor not found: scan_llm_file' }

    if (!$py.Contains('def _llm01_decision_policy(')) {
$helper = @'
def _llm01_decision_policy(finding: dict, content: str) -> dict:
    """Evidence-aware contextual decision policy for LLM01.

    Detection remains heuristic. This helper does not claim taint validation.
    """
    import re as _re
    text = str(content or '')
    snippet = str(finding.get('snippet') or '')
    model_re = _re.compile(r'(?:OpenAI\s*\(|Anthropic\s*\(|client\.(?:chat\.completions|responses)\.create\s*\(|\.(?:invoke|predict|generate|complete|completions\.create)\s*\(|(?:ChatOpenAI|AzureOpenAI|Bedrock|GenerativeModel)\s*\()', _re.I)
    prompt_flow_re = _re.compile(r'(?:input\s*\(|request\.(?:json|form|args|query_params)|user[_\s-]?input|user[_\s-]?prompt|user[_\s-]?message|request\.body|req\.body|message\s*=\s*user)', _re.I)
    system_prompt_re = _re.compile(r'(?:reveal|show|print|display|repeat|output|expose|leak).{0,120}(?:system\s+prompt|system\s+message|developer\s+message|hidden\s+instructions)', _re.I|_re.S)
    tool_sink_re = _re.compile(r'(?:tool\.(?:run|execute|call)|plugin\.execute|shell\.exec|browser\.(?:open|navigate)|subprocess\.|os\.system\s*\(|send[_\s-]?(?:email|message)|httpx?\.(?:post|put|request)\s*\()', _re.I)
    sensitive_sink_re = _re.compile(r'(?:secret|token|password|api[_-]?key|credential|private[_-]?key|system\s+prompt|hidden\s+instructions)', _re.I)
    model_invocation = bool(model_re.search(text))
    prompt_flow = bool(prompt_flow_re.search(text))
    system_prompt_request = bool(system_prompt_re.search(snippet) or system_prompt_re.search(text))
    tool_sink = bool(tool_sink_re.search(text))
    sensitive_sink = bool(sensitive_sink_re.search(snippet) or sensitive_sink_re.search(text))
    if not model_invocation:
        state, severity, priority, actionable = 'OBSERVED_ONLY', 'Low', 'P4', False
    elif model_invocation and prompt_flow and (system_prompt_request or tool_sink or sensitive_sink):
        state, severity, priority, actionable = 'HIGH_CONTEXTUAL_RISK', 'High', 'P2', True
    elif model_invocation and prompt_flow:
        state, severity, priority, actionable = 'CONTEXTUAL_RISK', 'Medium', 'P3', True
    else:
        state, severity, priority, actionable = 'MODEL_CONTEXT_OBSERVED', 'Low', 'P4', False
    reasons = []
    if model_invocation: reasons.append('model_invocation')
    if prompt_flow: reasons.append('prompt_flow')
    if system_prompt_request: reasons.append('system_prompt_request')
    if tool_sink: reasons.append('tool_sink')
    if sensitive_sink: reasons.append('sensitive_sink')
    return {
        'llm01_decision_policy_version': '1.0',
        'llm01_decision_state': state,
        'llm01_decision_reasons': reasons,
        'llm01_context': {'model_invocation': model_invocation, 'prompt_flow': prompt_flow, 'system_prompt_request': system_prompt_request, 'tool_sink': tool_sink, 'sensitive_sink': sensitive_sink},
        'actionable': actionable,
        'decision_confidence': 'HIGH' if len(reasons) >= 2 else 'MEDIUM',
        'decision_evidence_type': 'REGEX+CONTEXT',
        'decision_policy_applied': True,
        'decision_policy_version': 'LLM01-EAP-1.0',
        'severity': severity,
        'priority': priority,
    }

'@
        $py = $py.Replace($marker,$helper+$marker)
        Write-Host '[PASS] Installed LLM01 evidence-aware decision helper'
    }

    if (!$py.Contains("LLM01-EAP-1.0")) {
        $return = "`r`n    return findings"
        if (!$py.Contains($return)) { $return = "`n    return findings" }
        if (!$py.Contains($return)) { throw 'Required scanner return anchor not found' }
        $post = @'
    # Evidence-aware LLM01 decision pass. Existing PI detection is preserved.
    for _finding in findings:
        if _finding.get('rule_id') == 'LLM01_PROMPT_INJECTION':
            _finding.update(_llm01_decision_policy(_finding, content))

'@
        $py = $py.Replace($return,$post+$return)
        Write-Host '[PASS] Installed LLM01 contextual decision pass'
    }
    [IO.File]::WriteAllText($Scanner,$py,(New-Object Text.UTF8Encoding($false)))

    $fm = [IO.File]::ReadAllText($FindingModel,(New-Object Text.UTF8Encoding($false)))
    $old = @'
    if f['classification'] in {'heuristic','control_gap'}:
        # Heuristics/control gaps are never promoted to Critical/High solely by pattern.
        if str(f.get('severity','')).lower() in {'critical','high'}:
            f['severity'] = 'Medium' if f['classification'] == 'control_gap' else 'Low'
'@
    $new = @'
    if f['classification'] in {'heuristic','control_gap'}:
        # Permit only the explicit LLM01 evidence-aware policy to retain a
        # contextual High/Medium decision. Pattern-only heuristic findings
        # remain protected by the original downgrade guard.
        policy_applied = bool(f.get('decision_policy_applied'))
        policy_version = str(f.get('decision_policy_version') or '')
        if not (policy_applied and policy_version == 'LLM01-EAP-1.0' and f.get('evidence_valid', True) is not False):
            if str(f.get('severity','')).lower() in {'critical','high'}:
                f['severity'] = 'Medium' if f['classification'] == 'control_gap' else 'Low'
'@
    if ($fm.Contains($old)) {
        $fm = $fm.Replace($old,$new)
        [IO.File]::WriteAllText($FindingModel,$fm,(New-Object Text.UTF8Encoding($false)))
        Write-Host '[PASS] Installed finding-model decision-policy guard'
    } else { Write-Host '[WARN] Existing downgrade block not found; finding_model unchanged.' }

    python -m py_compile $Scanner
    python -m py_compile $FindingModel
    Write-Host '[PASS] Production compilation'
    python $testPath
    if ($LASTEXITCODE -ne 0) { throw 'Acceptance test failed' }
    Write-Host '============================================================'
    Write-Host 'R-SecOpsX V11 - LLM01 EVIDENCE-AWARE DECISION POLICY v1 ACCEPTED'
    Write-Host '============================================================'
    Write-Host '[PASS] Contextual LLM01 decisioning'
    Write-Host '[PASS] No blanket severity promotion'
    Write-Host '[PASS] No synthetic taint validation'
    Write-Host '[PASS] Persistent acceptance test'
    Write-Host '[PASS] Production backups retained under backup\'
}
catch {
    Write-Host '[FAIL] Patch/acceptance failed; restoring production files.'
    Copy-Item -LiteralPath $scannerBackup -Destination $Scanner -Force
    Copy-Item -LiteralPath $findingBackup -Destination $FindingModel -Force
    Write-Host '[PASS] Production source restored from backup.'
    throw
}
