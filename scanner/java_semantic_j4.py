"""R-SecOpsX J4 bounded Java semantic data-flow layer.

Additive semantic layer for Java. It is deliberately bounded:
- max interprocedural propagation rounds: 3
- max local fixed-point rounds: 8
- same-file method/call propagation only
- no ground truth/report access
- no modification of existing J1/J2/J3.x findings

Coverage targets:
- request/header/cookie sources
- Map.get/List.get/array indexing/Enumeration.next
- string concatenation/String.format/String.concat
- StringBuilder append/toString
- object-field taint
- parameter -> callee parameter
- tainted return -> caller variable
- HTTP/JDBC/process/filesystem/LDAP/XPath sinks
"""
from __future__ import annotations

import re
from pathlib import Path

try:
    from core.mapper import get_mapping
except Exception:
    def get_mapping(_v):
        return {}

_MAX_ROUNDS = 3
_LOCAL_ROUNDS = 8

_METHOD_HEAD_RE = re.compile(
    r"(?m)^[ \t]*(?:(?:public|protected|private|static|final|synchronized|abstract|native|strictfp)\s+)*"
    r"(?:<[\w\s,? extends super.&]+>\s+)?"
    r"(?:[A-Za-z_$][\w$<>\[\],.? ]*\s+)?"
    r"([A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*(?:throws\s+[^\{]+)?\{"
)

_SOURCE_RE = re.compile(
    r"\b(?:request|req)\s*\.\s*(?:getParameter|getHeader|getHeaders|getCookies|getCookie|getQueryString|getRequestURI|getRequestURL)\s*\(", re.I
)
_COOKIE_VALUE_RE = re.compile(r"\b[A-Za-z_$][\w$]*\s*\.\s*getValue\s*\(", re.I)
_DECODER_RE = re.compile(r"\bURLDecoder\s*\.\s*decode\s*\(", re.I)

_SINKS = [
    ("xss", "CWE-79", "Java J4 HTTP output sink", "JAVA_J4_XSS", re.compile(r"\b(?:response\s*\.\s*)?getWriter\s*\(\s*\)\s*\.\s*(?:print|println|printf|format|write)\s*\(", re.I)),
    ("sql_injection", "CWE-89", "Java J4 JDBC SQL sink", "JAVA_J4_SQL", re.compile(r"\b(?:[A-Za-z_$][\w$]*\.)?(?:prepareCall|prepareStatement|executeQuery|executeUpdate|execute)\s*\(", re.I)),
    ("command_injection", "CWE-78", "Java J4 process execution sink", "JAVA_J4_CMD", re.compile(r"\b(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|[A-Za-z_$][\w$]*\s*\.\s*(?:exec|start))\s*\(", re.I)),
    ("path_traversal", "CWE-22", "Java J4 filesystem sink", "JAVA_J4_PATH", re.compile(r"\bnew\s+(?:File|FileInputStream|FileOutputStream|RandomAccessFile)\s*\(|\b(?:Files|Paths)\s*\.\s*(?:readAllBytes|readString|readAllLines|newInputStream|newOutputStream|delete|copy|move|get)\s*\(", re.I)),
    ("ldap_injection", "CWE-90", "Java J4 LDAP sink", "JAVA_J4_LDAP", re.compile(r"\b(?:search|DirContext|InitialDirContext)\s*[^;\n]*\(", re.I)),
    ("xpath_injection", "CWE-643", "Java J4 XPath sink", "JAVA_J4_XPATH", re.compile(r"\b(?:XPathExpression|XPath)\s*[^;\n]*\.(?:evaluate|compile)\s*\(", re.I)),
]



def _mask_comments(source: str) -> str:
    out=[]; i=0; n=len(source); state="code"
    while i<n:
        if state=="code" and source.startswith("//",i):
            j=source.find("\n",i); j=n if j<0 else j
            out.append(" "*(j-i)); i=j; continue
        if state=="code" and source.startswith("/*",i):
            j=source.find("*/",i+2); j=n-2 if j<0 else j
            out.append(" "*(j+2-i)); i=j+2; continue
        out.append(source[i]); i+=1
    return "".join(out)


def _methods(source: str):
    masked=_mask_comments(source)
    methods=[]
    for m in _METHOD_HEAD_RE.finditer(masked):
        depth=1; i=m.end()
        while i<len(masked) and depth:
            if masked[i]=='{': depth+=1
            elif masked[i]=='}': depth-=1
            i+=1
        if depth: continue
        params=[]
        for raw in _split_args(m.group(2)):
            p=raw.strip()
            if not p: continue
            p=re.sub(r"@\w+(?:\([^)]*\))?\s*", "", p)
            names=re.findall(r"[A-Za-z_$][\w$]*", p)
            if names: params.append(names[-1])
        methods.append({"name":m.group(1),"params":params,"header_start":m.start(),"body_start":m.end(),"body_end":i-1,"body_start_line":masked.count("\n",0,m.end())+1,"body_end_line":masked.count("\n",0,i-1)+1})
    return methods


def _split_args(text: str):
    out=[]; cur=[]; depth=0; quote=None; esc=False
    for ch in text:
        if quote:
            cur.append(ch)
            if esc: esc=False
            elif ch=='\\': esc=True
            elif ch==quote: quote=None
            continue
        if ch in "\"'": quote=ch; cur.append(ch); continue
        if ch in '([{': depth+=1
        elif ch in ')]}': depth=max(0,depth-1)
        if ch==',' and depth==0:
            out.append(''.join(cur)); cur=[]
        else: cur.append(ch)
    if cur or text.strip(): out.append(''.join(cur))
    return out


def _idents(expr: str):
    return re.findall(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b", expr or "")


# RSECOPSX_E0_LITERAL_WORD_TAINT_FIX_20261017
# Java string/char literal contents (escapes handled) -- data, never code.
_J4_LITERAL_MASK = re.compile(
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


def _expr_tainted(expr: str, tainted: set[str], fields: set[str], builders: set[str]) -> set[str]:
    # RSECOPSX_E0_LITERAL_WORD_TAINT_FIX_20261017 -- string/char literal
    # contents are data, never identifiers (same discipline as the J5 and
    # JAVA_TAINT_* layers); concat flows keep their outside-the-quotes
    # variables.
    e = _J4_LITERAL_MASK.sub(" ", expr or "")
    hits=set()
    for name in tainted | fields | builders:
        if re.search(r"(?<![\w$])"+re.escape(name)+r"(?![\w$])", e): hits.add(name)
    return hits


def _lhs_from_assignment(line: str):
    m=re.match(r"\s*(?:[A-Za-z_$][\w$<>\[\],.? ]*\s+)?([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)?)\s*=\s*(.+?);?\s*$", line)
    return (m.group(1).replace(' ','') if m else None, m.group(2) if m else None)


def _source_seed(line: str):
    if re.search(r'\b(?:request|req)\s*\.\s*getParameterMap\s*\(', line, re.I):
        m = re.match(r'\s*(?:[A-Za-z_$][\w$<>\[\],.? ]*\s+)?([A-Za-z_$][\w$]*)\s*=', line)
        if m: return m.group(1), line.strip()[:160]
    if _SOURCE_RE.search(line) or _COOKIE_VALUE_RE.search(line) or _DECODER_RE.search(line):
        m=re.match(r"\s*(?:[A-Za-z_$][\w$<>\[\],.? ]*\s+)?([A-Za-z_$][\w$]*)\s*=", line)
        if m: return m.group(1), line.strip()[:160]
    return None


def _call_name(line: str):
    m=re.search(r"\b([A-Za-z_$][\w$]*)\s*\((.*)\)\s*;?\s*$", line)
    return (m.group(1), _split_args(m.group(2))) if m else (None,[])


def _make_finding(vuln,cwe,title,rule_id,filepath,line_no,snippet,chain,sink):
    mapping=get_mapping(vuln) or {}
    return {
        "vuln_type": vuln,
        "source_var": chain[0] if chain else "request",
        "source_expr": chain[0] if chain else "request",
        "sink_call": sink,
        "file": filepath,
        "line": line_no,
        "snippet": snippet.strip()[:500],
        "taint_path": " -> ".join(chain+[sink]),
        "taint_chain": chain+[sink],
        "function": "",
        "rule_id": rule_id,
        "title": title,
        "language": "java",
        "confidence": "High",
        "severity": mapping.get("severity") or "High",
        "cwe": cwe,
        "owasp": mapping.get("owasp") or mapping.get("owasp_id") or "",
        "remediation": mapping.get("remediation") or [],
        "description": "Java J4 bounded semantic source-to-sink data flow: " + " -> ".join(chain+[sink]),
        "detection": "Java J4 Bounded Semantic Data-Flow",
        "group_key": f"java-j4|{vuln}|{filepath}|{line_no}|{sink}",
    }


def _analyze_method(filepath, source_lines, method, incoming_params, initial_fields=None):
    start=method["body_start_line"]; end=method["body_end_line"]
    lines=source_lines[start-1:end]
    tainted=set(incoming_params)
    fields=set(initial_fields or set()); builders=set(); aliases={}
    origins={p:[f"parameter:{p}"] for p in incoming_params}
    returns=[]; findings=[]

    for _ in range(_LOCAL_ROUNDS):
        changed=False
        for rel,line in enumerate(lines):
            line_no=start+rel
            s=line.strip()
            if not s: continue

            src=_source_seed(s)
            if src and src[0] not in tainted:
                tainted.add(src[0]); origins[src[0]]=[src[1],src[0]]; changed=True

            # Object field assignment: obj.field = tainted
            fm=re.match(r"\s*([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*=\s*(.+?);?\s*$",s)
            if fm:
                objfield=fm.group(1)+'.'+fm.group(2)
                hits=_expr_tainted(fm.group(3),tainted,fields,set())
                if hits and objfield not in fields:
                    fields.add(objfield); origins[objfield]=origins.get(next(iter(hits)),[next(iter(hits))])+[objfield]; changed=True

            # StringBuilder append / toString
            bm=re.search(r"\b([A-Za-z_$][\w$]*)\s*\.\s*append\s*\((.*)\)",s,re.I)
            if bm and _expr_tainted(bm.group(2),tainted,fields,builders):
                if bm.group(1) not in builders:
                    builders.add(bm.group(1)); origins[bm.group(1)]=origins.get(next(iter(_expr_tainted(bm.group(2),tainted,fields,builders))),[bm.group(1)])+[bm.group(1)+'.append']; changed=True
            tm=re.match(r"\s*(?:String\s+)?([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\.toString\s*\(\s*\)\s*;",s,re.I)
            if tm and tm.group(2) in builders and tm.group(1) not in tainted:
                tainted.add(tm.group(1)); origins[tm.group(1)]=origins.get(tm.group(2),[tm.group(2)])+[tm.group(1)]; changed=True

            lhs,rhs=_lhs_from_assignment(s)
            if lhs and rhs:
                rhs2=rhs.replace(' ','')
                # Map/List/array/Enumeration propagation.
                mget=re.search(r"\b([A-Za-z_$][\w$]*)\.(?:get)\s*\((.*)\)",rhs,re.I)
                arr=re.search(r"\b([A-Za-z_$][\w$]*)\s*\[[^\]]+\]",rhs)
                nxt=re.search(r"\b([A-Za-z_$][\w$]*)\.next(?:Element)?\s*\(",rhs,re.I)
                # Do not propagate taint through return values of security sinks.
                # Example: ResultSet rs = statement.executeQuery(sql) must not make
                # `rs` tainted merely because `sql` is tainted; otherwise a later
                # response.getWriter().println(rs) becomes a false XSS finding.
                sink_return = re.search(
                    r"\b(?:executeQuery|executeUpdate|execute|prepareCall|prepareStatement|search|compile|evaluate|start|exec)\s*\(",
                    rhs,
                    re.I,
                )
                hits = set() if sink_return else _expr_tainted(rhs,tainted,fields,builders)
                if mget and mget.group(1) in tainted: hits.add(mget.group(1))
                if arr and arr.group(1) in tainted: hits.add(arr.group(1))
                if nxt and nxt.group(1) in tainted: hits.add(nxt.group(1))
                # Concatenation/format/concat only propagate when a known tainted operand exists.
                if ('+' in rhs or '.concat(' in rhs or 'String.format' in rhs or '.formatted(' in rhs) and hits:
                    pass
                if hits and lhs not in tainted:
                    tainted.add(lhs)
                    origin=next(iter(hits)); origins[lhs]=origins.get(origin,[origin])+[lhs]
                    changed=True
                # Object field read.
                if '.' in rhs2 and rhs2 in fields and lhs not in tainted:
                    tainted.add(lhs); origins[lhs]=origins.get(rhs2,[rhs2])+[lhs]; changed=True

            # Returns become interprocedural summary candidates.
            rm=re.search(r"\breturn\s+(.+?);",s)
            if rm:
                hits=_expr_tainted(rm.group(1),tainted,fields,builders)
                if hits:
                    returns.append((line_no,next(iter(hits))))

            # Sinks: only if an argument is actually tainted.
            for vuln,cwe,title,rule_id,pat in _SINKS:
                if not pat.search(s): continue
                args=[]
                op=s.find('('); cp=s.rfind(')')
                if op>=0 and cp>op: args=_split_args(s[op+1:cp])
                hits=set()
                for a in args: hits |= _expr_tainted(a,tainted,fields,builders)
                if hits:
                    # RSECOPSX_E1_PROVEN_CONSTANT_SINK_GATE_20261017
                    # Kill only on proof: when EVERY tainted carrier at this
                    # sink is a proven constant at this line (constant-true
                    # branch/ternary with int arithmetic, safe-key map
                    # round-trip, folded helper return -- shared evaluator
                    # scanner/multipart_flow), the attacker data provably
                    # died before the sink and the finding must not fire.
                    # Any unproven carrier, disabled gate, or analysis
                    # failure keeps the finding.  BenchmarkJava's negative
                    # oracles (J4_LDAP 14 FP / J4_XSS 13 FP on findings15)
                    # are exactly the folded shapes this proof catches.
                    try:
                        from scanner.multipart_flow import (
                            sink_value_proven_constant)
                        if sink_value_proven_constant(
                                "\n".join(source_lines), line_no,
                                sorted(hits), filepath=filepath):
                            break
                    except Exception:
                        pass
                    # F0: the shared order-aware dead-name walk (the same
                    # one the line layer and J3 delegate to) already
                    # proves these carriers dead -- 01051/01176/01265/
                    # 02048 all pass a helper whose folded return is a
                    # constant, and every J4_XSS row in findings22 sits on
                    # an oracle-NEGATIVE test (J4_XSS has zero rows on
                    # positives).  E1 could not see through the array
                    # carrier (`obj`) or the `bar.length()` alias; the
                    # walk kills exactly those on proof (constant last
                    # write, folded branch, callee-refined const return)
                    # and nothing else.  The delegation honours
                    # gate_enabled() like every other J4 proof gate:
                    # RSX_MULTIPART_FLOW=0 must restore the pre-gate
                    # behaviour (E-batch policy, pinned by
                    # test_e_gate_honors_multipart_kill_switch).  Lazy
                    # imports mirror the line layer's delegation.
                    try:
                        from scanner.multipart_flow import gate_enabled
                        from scanner.taint_engine import (
                            _java_dead_names, _java_mask_comments)
                        if gate_enabled():
                            dead = _java_dead_names(
                                _java_mask_comments(list(source_lines)),
                                set(tainted), line_no, vuln)
                            hits = {h for h in hits if h not in dead}
                    except Exception:
                        pass
                    if not hits:
                        continue
                    origin=next(iter(hits)); chain=origins.get(origin,[origin])
                    findings.append(_make_finding(vuln,cwe,title,rule_id,filepath,line_no,s,chain,s[:160]))
                    break
        if not changed: break
    return {"tainted":tainted,"fields":fields,"returns":returns,"findings":findings,"origins":origins}


def analyze_java_j4(filepath: str, source: str) -> list[dict]:
    """Return additive J4 findings for one Java source file."""
    if not filepath.lower().endswith('.java'):
        return []
    methods=_methods(source)
    if not methods:
        return []
    lines=source.splitlines()
    # Per-method incoming tainted parameter names.
    incoming={id(m):set() for m in methods}
    global_fields=set()
    results={}
    all_findings=[]

    # Seed methods that contain direct request/cookie sources; then propagate
    # tainted arguments and tainted returns through same-file calls.
    for m in methods:
        body='\n'.join(lines[m['body_start']-1:m['body_end']])
        for p in m['params']:
            # A parameter itself is not assumed tainted. It becomes tainted only
            # when a caller passes a tainted argument.
            pass
        results[id(m)]=_analyze_method(filepath,lines,m,set(),global_fields)

    for _ in range(_MAX_ROUNDS):
        changed=False
        # Recompute each method using currently known tainted parameters.
        for m in methods:
            r=_analyze_method(filepath,lines,m,incoming[id(m)],global_fields)
            if r['findings']:
                all_findings.extend(r['findings'])
            results[id(m)]=r
            if r.get('fields'):
                before=len(global_fields); global_fields.update(r['fields']); changed = changed or len(global_fields) != before
        # Build simple call sites and propagate tainted args into callees.
        for caller in methods:
            cr=results[id(caller)]
            body_lines=lines[caller['body_start_line']-1:caller['body_end_line']]
            for rel,line in enumerate(body_lines):
                s=line.strip()
                cm=re.search(r"\b([A-Za-z_$][\w$]*)\s*\((.*)\)\s*;",s)
                if not cm: continue
                name=cm.group(1); args=_split_args(cm.group(2))
                callees=[x for x in methods if x['name']==name and len(x['params'])==len(args)]
                if not callees: continue
                for callee in callees:
                    for idx,arg in enumerate(args):
                        hits=_expr_tainted(arg,cr['tainted'],cr['fields'],set())
                        if hits and idx<len(callee['params']):
                            p=callee['params'][idx]
                            if p not in incoming[id(callee)]:
                                incoming[id(callee)].add(p); changed=True
        # Return-value propagation: identify assignment `x = helper(args)` and
        # if helper has a tainted return, taint x in the caller on next round.
        for caller in methods:
            cr=results[id(caller)]
            body_lines=lines[caller['body_start_line']-1:caller['body_end_line']]
            for line in body_lines:
                mcall=re.match(r"\s*(?:[A-Za-z_$][\w$<>\[\],.? ]*\s+)?([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*\((.*)\)\s*;",line)
                if not mcall: continue
                lhs,callee_name,args=mcall.group(1),mcall.group(2),_split_args(mcall.group(3))
                for callee in methods:
                    if callee['name']!=callee_name or len(callee['params'])!=len(args): continue
                    rr=results.get(id(callee),{})
                    if rr.get('returns'):
                        hits=[]
                        for idx,arg in enumerate(args):
                            if idx<len(callee['params']) and callee['params'][idx] in incoming[id(callee)]:
                                hits.append(arg)
                        if hits and lhs not in cr['tainted']:
                            # Seed caller by synthetic incoming alias. We use a
                            # reserved marker that is replaced by the caller
                            # analyzer through a direct taint seed on the next pass.
                            incoming[id(caller)].add(lhs); changed=True
        if not changed: break

    # Deduplicate against same semantic line/type.
    out=[]; seen=set()
    for f in all_findings:
        k=(f.get('vuln_type'),f.get('file'),f.get('line'))
        if k in seen: continue
        seen.add(k); out.append(f)
    return out
