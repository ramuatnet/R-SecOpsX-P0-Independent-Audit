"""T-9.6 D-2 triage SPA -- one static HTML+JS asset, no server, no build.

opencodetask D-2 (G18, task.md §12 UI): an airgap-friendly triage view
that reads ``clean_report.json`` two ways --

* **fetch mode** (``build_asset()``): the shipped asset sits next to a
  report and fetches ``./clean_report.json`` relative to itself.  Works
  over HTTP; most browsers BLOCK fetch from ``file://`` (opaque origin),
  so the page surfaces an honest load-failure message pointing at both
  remedies instead of rendering an empty shell.
* **embedded mode** (``build(report)``): ``--html-embedded`` on the CLI
  (or this module's ``--report``) writes the triage subset INTO the
  HTML, so the file opens offline over ``file://`` with zero network.

Contracts (pinned by tests/test_t96_triage_spa.py):

* single vanilla HTML+JS string -- no framework, no build step,
  no CDN references (airgap);
* deterministic: same report -> byte-identical HTML (canonical subset
  JSON, sort_keys, no clocks; the only times shown come from the
  report's own metadata);
* size budget: the asset (template) stays <= 250 KB (D-2 gate; KB
  interpreted as KiB = 250*1024 bytes -- disclosed);
* views: list + severity/rule/CWE/OWASP/verdict filters (options built
  from the data, never hard-coded vocabularies), evidence expand,
  suppression workflow emitting a baseline patch stub download in the
  ``baseline/sast_baseline.json`` shape ``{rule_id: [{file, line}]}``
  (accuracy/suppressions.py consumes it);
* the embedded JSON is escaped (``<`` ``&`` U+2028/9) so a finding
  payload can never break out of its script tag (stored XSS);
* display only -- NO client-side policy logic (web_ui doc §4.5): every
  value shown was computed by the scanner, never upgraded in the
  browser.
"""
from __future__ import annotations

import argparse
import json

SCHEMA = "rsecopsx.triage_spa/v1"
ASSET_BUDGET_BYTES = 250 * 1024      # D-2 "≤ 250 KB" (KiB, disclosed)

# fields kept per finding (the triage subset -- small enough to embed)
_ROW_KEYS = (
    "id", "rule_id", "title", "severity", "cwe", "owasp", "verdict",
    "disposition", "file", "line", "confidence", "vuln_type", "snippet",
    "evidence", "description",
)


def _text(value):
    """JSON-stable text (round-trips identically through clean_report)."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return value
    return str(value)


def _line(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.lstrip("-").isdigit():
        return int(value)
    return None


def _row(finding: dict) -> dict:
    """One triage row; missing fields stay null (honest, never faked)."""
    accuracy = finding.get("accuracy")
    if not isinstance(accuracy, dict):
        accuracy = {}
    verdict = accuracy.get("verdict")
    if verdict is not None:
        verdict = str(verdict)
    evidence = finding.get("evidence")
    if not isinstance(evidence, list):
        evidence = []
    fid = finding.get("finding_id") or finding.get("fingerprint")
    if not fid:
        fid = "%s:%s:%s" % (finding.get("rule_id"), finding.get("file"),
                            finding.get("line"))
    row = {
        "id": str(fid),
        "rule_id": _text(finding.get("rule_id")),
        "title": _text(finding.get("title") or finding.get("vuln_type")
                       or finding.get("rule_id")),
        "severity": _text(finding.get("severity")),
        "cwe": _text(finding.get("cwe")),
        "owasp": _text(finding.get("owasp")),
        "verdict": verdict,
        "disposition": _text(finding.get("disposition")),
        "file": _text(finding.get("file")),
        "line": _line(finding.get("line")),
        "confidence": _text(finding.get("confidence")),
        "vuln_type": _text(finding.get("vuln_type")),
        "snippet": _text(finding.get("snippet")),
        "evidence": [str(e) for e in evidence],
        "description": _text(finding.get("description")),
    }
    return {k: row[k] for k in _ROW_KEYS}


def triage_subset(report: dict) -> dict:
    """Deterministic embeddable subset of a clean_report payload."""
    meta = report.get("metadata")
    if not isinstance(meta, dict):
        meta = {}
    findings = report.get("findings")
    if not isinstance(findings, list):
        findings = []
    return {
        "schema": SCHEMA,
        "report": {
            "tool": _text(meta.get("tool")),
            "scan_date": _text(meta.get("scan_date")),
            "total_findings": _text(meta.get("total_findings")),
            "sast_findings": _text(meta.get("sast_findings")),
            "sca_findings": _text(meta.get("sca_findings")),
        },
        "findings": [_row(f) for f in findings if isinstance(f, dict)],
    }


def _safe_json(obj) -> str:
    """Canonical JSON that cannot break out of a <script> tag."""
    raw = json.dumps(obj, sort_keys=True, ensure_ascii=True,
                     separators=(",", ":"))
    return (raw.replace("<", "\\u003c").replace("&", "\\u0026")
               .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>R-SecOpsX Triage</title>
<style>
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin: 0; font: 14px/1.45 system-ui, -apple-system, "Segoe UI",
       sans-serif; background: #f6f7f9; color: #1c2733; }
@media (prefers-color-scheme: dark) {
  body { background: #14181d; color: #dfe6ee; }
  table, .detail { background: #1b2129 !important; }
  th { background: #232b35 !important; }
  input, select, button { background: #232b35 !important;
    color: #dfe6ee !important; border-color: #3a4552 !important; }
}
header { padding: 14px 18px 8px; }
h1 { margin: 0 0 6px; font-size: 18px; }
#provenance { font-size: 12px; opacity: .85; margin-bottom: 8px; }
#filters { display: flex; flex-wrap: wrap; gap: 6px; align-items: center;
           margin-bottom: 8px; }
#filters input, #filters select { padding: 4px 6px; }
#counts { font-size: 12px; opacity: .85; margin-left: auto; }
main { padding: 0 18px 24px; }
#error { background: #b3261e; color: #fff; padding: 10px 12px;
         border-radius: 6px; margin: 8px 0; white-space: pre-wrap; }
table { border-collapse: collapse; width: 100%; background: #fff; }
th, td { border: 1px solid #d5dbe3; padding: 5px 8px; text-align: left;
         vertical-align: top; }
th { background: #eceff4; font-size: 12px; cursor: default; }
tr.row { cursor: pointer; }
tr.row:hover { outline: 1px solid #7aa2e8; }
.sev-Critical { border-left: 4px solid #8b0000; }
.sev-High { border-left: 4px solid #d93025; }
.sev-Medium { border-left: 4px solid #f9ab00; }
.sev-Low { border-left: 4px solid #1a73e8; }
.detail { background: #fbfcfe; }
.detail td { font-size: 13px; }
.detail pre { margin: 4px 0; padding: 6px; background: #eef1f6;
              overflow-x: auto; white-space: pre-wrap; word-break: break-all;
              }
.detail ul { margin: 4px 0; padding-left: 18px; }
#stubbar { margin: 10px 0; display: flex; gap: 8px; align-items: center; }
.empty { padding: 16px; opacity: .8; }
button { cursor: pointer; }
</style>
</head>
<body>
<header>
<h1>R-SecOpsX Triage</h1>
<div id="provenance">loading&hellip;</div>
<div id="filters">
<input id="q" type="search" placeholder="search title/rule/file"
       aria-label="search">
<select id="f-severity" aria-label="severity filter"><option value="">severity: all</option></select>
<select id="f-rule" aria-label="rule filter"><option value="">rule: all</option></select>
<select id="f-cwe" aria-label="cwe filter"><option value="">CWE: all</option></select>
<select id="f-owasp" aria-label="owasp filter"><option value="">OWASP: all</option></select>
<select id="f-verdict" aria-label="verdict filter"><option value="">verdict: all</option></select>
<button id="reset" type="button">reset</button>
<span id="counts"></span>
</div>
</header>
<main>
<div id="error" hidden></div>
<div id="stubbar">
<button id="stub" type="button" disabled>download baseline stub (0)</button>
<span id="stubhint" style="font-size:12px;opacity:.8"></span>
</div>
<table id="list">
<thead><tr><th>sev</th><th>rule</th><th>CWE</th><th>OWASP</th>
<th>verdict</th><th>file:line</th><th>title</th></tr></thead>
<tbody id="rows"></tbody>
</table>
<div id="empty" class="empty" hidden>no findings match the current filters</div>
</main>
<script id="rsx-triage-data" type="application/json">__DATA__</script>
<script>
(function () {
"use strict";
var SCHEMA = "rsecopsx.triage_spa/v1";
function el(id) { return document.getElementById(id); }
function showErr(msg) { var e = el("error"); e.hidden = false; e.textContent = msg; }
function normRow(f) { return f; }
function rowFromFull(f) {
  var acc = (f && typeof f === "object" && f.accuracy) ? f.accuracy : {};
  return {
    id: (f.finding_id || f.fingerprint || (f.rule_id + ":" + f.file + ":" + f.line)),
    rule_id: f.rule_id != null ? f.rule_id : null,
    title: (f.title || f.vuln_type || f.rule_id || ""),
    severity: f.severity != null ? f.severity : null,
    cwe: f.cwe != null ? f.cwe : null,
    owasp: f.owasp != null ? f.owasp : null,
    verdict: acc.verdict != null ? acc.verdict : null,
    disposition: f.disposition != null ? f.disposition : null,
    file: f.file != null ? f.file : null,
    line: (typeof f.line === "number" ? f.line : null),
    confidence: f.confidence != null ? f.confidence : null,
    vuln_type: f.vuln_type != null ? f.vuln_type : null,
    snippet: f.snippet != null ? f.snippet : null,
    evidence: Array.isArray(f.evidence) ? f.evidence : [],
    description: f.description != null ? f.description : null
  };
}
function normalize(doc) {
  if (doc && doc.schema === SCHEMA) {
    return { report: doc.report || {}, rows: (doc.findings || []).map(normRow) };
  }
  var meta = (doc && doc.metadata) ? doc.metadata : {};
  var fs = (doc && Array.isArray(doc.findings)) ? doc.findings : [];
  return { report: meta, rows: fs.map(rowFromFull) };
}
var DATA = [], selected = {}, filters =
  { q: "", severity: "", rule: "", cwe: "", owasp: "", verdict: "" };
function text(v) { return (v === null || v === undefined || v === "") ? "\u2014" : String(v); }
function distinct(key) {
  var seen = {}, out = [];
  for (var i = 0; i < DATA.length; i++) {
    var v = DATA[i][key];
    if (v === null || v === undefined || v === "") continue;
    var s = String(v);
    if (!seen[s]) { seen[s] = 1; out.push(s); }
  }
  out.sort();
  return out;
}
function fillSelect(id, dataKey, filterKey) {
  var sel = el(id), vals = distinct(dataKey);
  for (var i = 0; i < vals.length; i++) {
    var o = document.createElement("option");
    o.value = vals[i]; o.textContent = vals[i];
    sel.appendChild(o);
  }
  sel.addEventListener("change", function () {
    filters[filterKey] = sel.value; render();
  });
}
function matches(r) {
  if (filters.severity && String(r.severity) !== filters.severity) return false;
  if (filters.rule && String(r.rule_id) !== filters.rule) return false;
  if (filters.cwe && String(r.cwe) !== filters.cwe) return false;
  if (filters.owasp && String(r.owasp) !== filters.owasp) return false;
  if (filters.verdict && String(r.verdict) !== filters.verdict) return false;
  if (filters.q) {
    var hay = [r.title, r.rule_id, r.file, r.cwe, r.owasp]
      .map(function (v) { return v == null ? "" : String(v).toLowerCase(); })
      .join(" ");
    if (hay.indexOf(filters.q) === -1) return false;
  }
  return true;
}
function td(parent, cls, val) {
  var c = document.createElement("td");
  if (cls) c.className = cls;
  c.textContent = text(val);
  parent.appendChild(c);
  return c;
}
function fillEvidence(cell, r) {
  var pre = document.createElement("pre");
  pre.textContent = r.snippet != null ? String(r.snippet) : "\u2014";
  cell.appendChild(pre);
  if (Array.isArray(r.evidence) && r.evidence.length) {
    var ul = document.createElement("ul");
    for (var i = 0; i < r.evidence.length; i++) {
      var li = document.createElement("li");
      li.textContent = String(r.evidence[i]);
      ul.appendChild(li);
    }
    cell.appendChild(ul);
  }
  if (r.description) {
    var p = document.createElement("p");
    p.textContent = String(r.description);
    cell.appendChild(p);
  }
  var meta = document.createElement("div");
  meta.textContent = "disposition: " + text(r.disposition) +
    " | confidence: " + text(r.confidence);
  cell.appendChild(meta);
}
function stubJson(ids) {
  var picked = {};
  for (var i = 0; i < DATA.length; i++) {
    var r = DATA[i];
    if (!ids[r.id] || r.file == null) continue;
    var rule = String(r.rule_id || "UNKNOWN");
    if (!picked[rule]) picked[rule] = [];
    var entry = { file: String(r.file) };
    if (r.line != null) entry.line = r.line;
    picked[rule].push(entry);
  }
  var rules = Object.keys(picked).sort(), out = {};
  for (var j = 0; j < rules.length; j++) {
    picked[rules[j]].sort(function (a, b) {
      return a.file === b.file ? (a.line || 0) - (b.line || 0)
                               : (a.file < b.file ? -1 : 1);
    });
    out[rules[j]] = picked[rules[j]];
  }
  return JSON.stringify(out, null, 2) + "\\n";
}
function updateStubBar() {
  var n = 0;
  for (var k in selected) { if (selected[k]) n++; }
  var btn = el("stub");
  btn.textContent = "download baseline stub (" + n + ")";
  btn.disabled = n === 0;
  el("stubhint").textContent = n === 0
    ? "expand a row and press suppress to build a baseline/sast_baseline.json patch stub"
    : "stub shape: {rule_id: [{file, line}]} -- merge into baseline/sast_baseline.json";
}
function render() {
  var body = el("rows");
  while (body.firstChild) body.removeChild(body.firstChild);
  var shown = 0;
  for (var i = 0; i < DATA.length; i++) {
    var r = DATA[i];
    if (!matches(r)) continue;
    shown++;
    var tr = document.createElement("tr");
    tr.className = "row";
    var sevCls = r.severity ? "sev-" + String(r.severity) : "";
    td(tr, sevCls, r.severity);
    td(tr, "", r.rule_id);
    td(tr, "", r.cwe);
    td(tr, "", r.owasp);
    td(tr, "", r.verdict);
    td(tr, "", r.file != null && r.line != null ? r.file + ":" + r.line : r.file);
    td(tr, "", r.title);
    body.appendChild(tr);
    var detail = document.createElement("tr");
    detail.className = "detail";
    detail.hidden = true;
    var dcell = document.createElement("td");
    dcell.colSpan = 7;
    fillEvidence(dcell, r);
    detail.appendChild(dcell);
    body.appendChild(detail);
    (function (det, row) {
      tr.addEventListener("click", function () { det.hidden = !det.hidden; });
      var sup = document.createElement("button");
      sup.type = "button";
      sup.textContent = selected[row.id] ? "unsuppress" : "suppress";
      sup.addEventListener("click", function (ev) {
        ev.stopPropagation();
        selected[row.id] = !selected[row.id];
        sup.textContent = selected[row.id] ? "unsuppress" : "suppress";
        updateStubBar();
      });
      dcell.appendChild(sup);
    })(detail, r);
  }
  el("empty").hidden = shown !== 0;
  el("counts").textContent = shown + " / " + DATA.length + " findings";
}
function boot(doc) {
  var model = normalize(doc);
  DATA = model.rows;
  var rep = model.report || {};
  var bits = [];
  if (rep.tool) bits.push("tool: " + rep.tool);
  if (rep.scan_date) bits.push("scanned: " + rep.scan_date);
  bits.push("findings in artifact: " + text(rep.total_findings != null
    ? rep.total_findings : DATA.length));
  if (rep.sast_findings != null) bits.push("sast: " + rep.sast_findings);
  if (rep.sca_findings != null) bits.push("sca: " + rep.sca_findings);
  el("provenance").textContent = bits.join(" | ");
  fillSelect("f-severity", "severity", "severity");
  fillSelect("f-rule", "rule_id", "rule");
  fillSelect("f-cwe", "cwe", "cwe");
  fillSelect("f-owasp", "owasp", "owasp");
  fillSelect("f-verdict", "verdict", "verdict");
  el("q").addEventListener("input", function () {
    filters.q = el("q").value.trim().toLowerCase(); render();
  });
  el("reset").addEventListener("click", function () {
    filters = { q: "", severity: "", rule: "", cwe: "", owasp: "", verdict: "" };
    el("q").value = "";
    var sels = ["f-severity", "f-rule", "f-cwe", "f-owasp", "f-verdict"];
    for (var i = 0; i < sels.length; i++) el(sels[i]).value = "";
    render();
  });
  el("stub").addEventListener("click", function () {
    var json = stubJson(selected);
    var blob = new Blob([json],
      { type: "application/json" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "sast_baseline_patch.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  });
  updateStubBar();
  render();
  window.__rsx = { rows: function () { return DATA.slice(); },
                   matches: matches, stubJson: stubJson, boot: boot };
}
function fromRaw(raw) {
  try {
    boot(JSON.parse(raw));
  } catch (e) {
    showErr("embedded data is not valid JSON: " + e);
  }
}
var dataEl = el("rsx-triage-data");
var raw = dataEl ? (dataEl.textContent || "").trim() : "";
if (raw) {
  fromRaw(raw);
} else {
  fetch("./clean_report.json", { cache: "no-store" })
    .then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.text();
    })
    .then(fromRaw)
    .catch(function (e) {
      showErr("could not load ./clean_report.json (" + e + ").\\n" +
        "Most browsers block fetch() from file:// pages.\\n" +
        "Remedies: generate an embedded copy (--html-embedded, or " +
        "python -m reporting.triage_spa --report clean_report.json " +
        "--out triage.html) or serve this folder over HTTP.");
    });
}
})();
</script>
</body>
</html>
"""


def build(report: dict | None = None, embedded: bool = True) -> bytes:
    """The SPA as bytes.

    ``embedded=True`` bakes ``report``'s triage subset into the page
    (file:// safe).  ``embedded=False`` emits the fetch-mode asset with
    an empty data tag -- ``report`` is ignored by design.
    """
    data = _safe_json(triage_subset(report or {})) if embedded else ""
    html = _HEAD.replace("__DATA__", data)
    return html.encode("utf-8")


def build_asset() -> bytes:
    """The shipped fetch-mode asset (reads ./clean_report.json)."""
    return build(None, embedded=False)


def main(argv=None) -> int:
    """CLI: (--asset | --report PATH) --out PATH.

    rc0 written, rc1 unreadable/invalid report (loud, never partial),
    rc2 usage (argparse).
    """
    ap = argparse.ArgumentParser(
        prog="python -m reporting.triage_spa",
        description="Build the D-2 airgap triage SPA (static HTML+JS).")
    ap.add_argument("--report", help="clean_report.json to embed")
    ap.add_argument("--asset", action="store_true",
                    help="write the fetch-mode asset (no report needed)")
    ap.add_argument("--out", required=True, help="output .html path")
    args = ap.parse_args(argv)
    if bool(args.report) == bool(args.asset):
        ap.error("exactly one of --report or --asset is required")
    try:
        if args.asset:
            blob = build_asset()
        else:
            with open(args.report, "r", encoding="utf-8") as fh:
                report = json.load(fh)
            if not isinstance(report, dict):
                raise ValueError("report root is not a JSON object")
            blob = build(report, embedded=True)
        with open(args.out, "wb") as fh:
            fh.write(blob)
    except (OSError, ValueError) as exc:
        print(f"triage spa error: {type(exc).__name__}: {exc}")
        return 1
    print(f"       => {args.out} ({len(blob)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
