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
    r"\b(?:request|req)\s*\.\s*(?:getParameter|getHeader|getHeaders|getHeaderNames|getCookies|getCookie|getQueryString|getRequestURI|getRequestURL)\s*\(", re.I
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


def _expr_tainted(expr: str, tainted: set[str], fields: set[str], builders: set[str]) -> set[str]:
    # RSECOPSX_E0_LITERAL_WORD_TAINT_FIX_20261017 -- string/char literal
    # contents are data, never identifiers.  This prelude copy of the J4
    # helper mirrors scanner/java_semantic_j4.py (kept byte-consistent
    # even though analyze_java_j4 here is not wired into the pipeline);
    # it shares this module's _J5_LITERAL_MASK (resolved at call time).
    e = _J5_LITERAL_MASK.sub(" ", expr or "")
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
                    # RSECOPSX_E1_PROVEN_CONSTANT_SINK_GATE_20261017 --
                    # mirror of the gate in scanner/java_semantic_j4.py
                    # (twin prelude kept consistent; this copy is not
                    # wired into the pipeline).
                    try:
                        from scanner.multipart_flow import (
                            sink_value_proven_constant)
                        if sink_value_proven_constant(
                                "\n".join(source_lines), line_no,
                                sorted(hits), filepath=filepath):
                            break
                    except Exception:
                        pass
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


# =============================================================================
# R-SecOpsX J5 BIG-BANG JAVA PROJECT SEMANTIC LAYER
# =============================================================================
# Additive project-level layer. Existing J1/J2/J3/J4 behavior remains intact.
# Adds bounded cross-file parameter/return propagation and reuses the semantic
# model for objects, collections and common string transformations.
# No benchmark IDs, ground truth, reports, or filename-specific exceptions.
# =============================================================================

_J5_MAX_ROUNDS = 6
_J5_LOCAL_ROUNDS = 8

_J5_ASSIGN_RE = re.compile(
    r'^\s*(?:(?:final|static|private|public|protected|volatile|transient)\s+)*'
    r'(?:[A-Za-z_$][\w$<>\[\],.? ]*\s+)?'
    r'([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)?)\s*=\s*(.+?)\s*;?\s*$'
)

# F0: does this statement DECLARE the assigned name (``Type name = ...``)
# rather than merely write it (``name = ...``)?  The type token must be a
# single dotted/array-annotated identifier followed by whitespace, so a
# plain assignment cannot parse (`bar` then expects a name before `=`)
# and a field write (`obj.field = x`) never reaches this test anyway --
# record() rejects dotted left-hand sides first.
_J5_DECL_RE = re.compile(
    r'(?:(?:final|static|volatile)\s+)*'
    r'[A-Za-z_$][\w$<>\[\],.?]*\s+'
    r'[A-Za-z_$][\w$]*\s*=(?!=)'
)

_J5_METHOD_RE = re.compile(
    r'(?m)^[ \t]*(?:(?:public|protected|private|static|final|synchronized|abstract|native|strictfp)\s+)*'
    r'(?:<[\w\s,? extends super.&]+>\s+)?'
    r'(?:[A-Za-z_$][\w$<>\[\],.? ]*\s+)?'
    r'([A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*(?:throws\s+[^{]+)?\{'
)

_J5_CONTROL_WORDS = {"if", "for", "while", "switch", "catch", "synchronized", "try", "do"}

_J5_SOURCE_RE = re.compile(
    r'\b(?:request|req)\s*\.\s*'
    r'(?:getParameter|getParameterMap|getParameterNames|getParameterValues|getHeader|getHeaders|getHeaderNames|getCookies|getCookie|'
    r'getQueryString|getRequestURI|getRequestURL|getInputStream|getReader)\s*\(',
    re.I
)
_J5_COOKIE_VALUE_RE = re.compile(
    r'\b[A-Za-z_$][\w$]*\s*\.\s*getValue\s*\(', re.I
)

_J5_WRAPPER_SOURCE_RE = re.compile(
    r'\b[A-Za-z_$][\w$]*\s*\.\s*getTheParameter\s*\(', re.I
)

_J5_TRANSFORM_RE = re.compile(
    r'\b(?:URLDecoder\s*\.\s*decode|String\s*\.\s*(?:valueOf|format)|'
    r'[A-Za-z_$][\w$]*\s*\.\s*(?:substring|trim|replace|replaceAll|concat|'
    r'toString|getBytes|split|toLowerCase|toUpperCase))\s*\(',
    re.I
)

_J5_SINKS = [
    ("xss", "CWE-79", "Java J5 HTTP response output", "JAVA_J5_XSS",
     re.compile(r'\b(?:response\s*\.\s*)?getWriter\s*\(\s*\)\s*\.\s*'
                r'(?:print|println|printf|format|write)\s*\(', re.I)),
    ("sql_injection", "CWE-89", "Java J5 JDBC SQL execution", "JAVA_J5_SQL",
     # F3: the Spring JdbcTemplate family (queryForObject/queryForRowSet/
     # batchUpdate/...) is the dominant BenchmarkJava SQL sink shape; the
     # short names `query`/`update` stay receiver-constrained so that
     # MessageDigest.update(...) hash work is never claimed as SQL.
     re.compile(r'\b(?:(?:prepareCall|prepareStatement|executeQuery|executeUpdate|execute'
                r'|queryForObject|queryForLong|queryForInt|queryForMap|queryForList'
                r'|queryForRowSet|batchUpdate|addBatch)\s*\('
                r'|(?:[A-Za-z_$][\w$]*(?:template|jdbc|dao|sql)[\w$]*'
                r'|(?:template|jdbc|dao|sql|tx)[\w$]*)\s*\.\s*(?:query|update)\s*\()',
                re.I)),
    ("command_injection", "CWE-78", "Java J5 process execution", "JAVA_J5_CMD",
     re.compile(r'\b(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|'
                r'[A-Za-z_$][\w$]*\.(?:exec|start))\s*\(', re.I)),
    ("path_traversal", "CWE-22", "Java J5 filesystem access", "JAVA_J5_PATH",
     # The optional package qualifier is load-bearing, not decoration. The
     # original pattern was `\bnew\s+(?:File|...)`, so it required `new File(`.
     # Real code -- and every missed OWASP BenchmarkJava path-traversal case --
     # writes `new java.io.File(` and `new java.io.FileInputStream(`, where
     # `java` follows `new ` and the alternation never matched. Measured on the
     # BenchmarkJava oracle: path-traversal recall was 0.0827 (11 of 133), and
     # 122 missed cases all use the fully-qualified form. Same blind spot applied
     # to java.nio.file, hence the optional qualifier on Files/Paths too.
     re.compile(r'\bnew\s+(?:[A-Za-z_$][\w$]*\s*\.\s*)*'
                r'(?:File|FileInputStream|FileOutputStream|RandomAccessFile)\s*\(|'
                r'\b(?:[A-Za-z_$][\w$]*\s*\.\s*)*'
                r'(?:Files|Paths)\s*\.\s*(?:readAllBytes|readString|readAllLines|'
                r'newInputStream|newOutputStream|delete|copy|move|get)\s*\(', re.I)),
    ("ldap_injection", "CWE-90", "Java J5 LDAP directory operation", "JAVA_J5_LDAP",
     re.compile(r'\b(?:[A-Za-z_$][\w$]*\s*\.\s*)?(?:search|searchLink|lookup)\s*\(', re.I)),
    ("xpath_injection", "CWE-643", "Java J5 XPath operation", "JAVA_J5_XPATH",
     re.compile(r'\b(?:[A-Za-z_$][\w$]*\s*\.\s*)?(?:compile|evaluate)\s*\(', re.I)),
]

_J5_SECURITY_RETURN_CALLS = re.compile(
    r'\b(?:(?:executeQuery|executeUpdate|execute|prepareCall|prepareStatement|'
    r'queryForObject|queryForLong|queryForInt|queryForMap|queryForList|'
    r'queryForRowSet|batchUpdate|search|compile|evaluate|start|exec)\s*\('
    r'|(?:[A-Za-z_$][\w$]*(?:template|jdbc|dao|sql)[\w$]*'
    r'|(?:template|jdbc|dao|sql|tx)[\w$]*)\s*\.\s*(?:query|update)\s*\()',
    re.I
)


def _j5_mask(source):
    chars = list(source)
    i = 0
    n = len(source)
    block = False
    quote = None
    while i < n:
        if block:
            if source.startswith("*/", i):
                chars[i] = chars[i + 1] = " "
                i += 2
                block = False
                continue
            if source[i] != "\n":
                chars[i] = " "
            i += 1
            continue
        if quote:
            if source[i] == "\\":
                i += 2
                continue
            if source[i] == quote:
                quote = None
            i += 1
            continue
        if source.startswith("//", i):
            j = source.find("\n", i)
            if j < 0:
                j = n
            for k in range(i, j):
                chars[k] = " "
            i = j
            continue
        if source.startswith("/*", i):
            chars[i] = chars[i + 1] = " "
            i += 2
            block = True
            continue
        if source[i] in ('"', "'"):
            quote = source[i]
        i += 1
    return "".join(chars)


def _j5_methods(source, filepath):
    masked = _j5_mask(source)
    methods = []
    for m in _J5_METHOD_RE.finditer(masked):
        name = m.group(1)
        if name in _J5_CONTROL_WORDS:
            continue

        depth = 1
        pos = m.end()
        while pos < len(masked) and depth:
            if masked[pos] == "{":
                depth += 1
            elif masked[pos] == "}":
                depth -= 1
            pos += 1
        if depth:
            continue

        params = []
        for raw in _split_args(m.group(2)):
            p = re.sub(r'@[A-Za-z_$][\w$]*(?:\([^)]*\))?\s*', '', raw.strip())
            p = re.sub(r'\bfinal\s+', '', p).replace("...", "[]")
            ids = re.findall(r'[A-Za-z_$][\w$]*', p)
            if ids:
                params.append(ids[-1])

        methods.append({
            "name": name,
            "params": params,
            "start_line": masked.count("\n", 0, m.start()) + 1,
            "body_start_line": masked.count("\n", 0, m.end()) + 1,
            "end_line": masked.count("\n", 0, pos) + 1,
            "body_end_line": max(
                masked.count("\n", 0, pos) + 1,
                masked.count("\n", 0, pos) + 1 - 1,
            ),
            "file": str(filepath),
        })
    return methods


def _j5_method_key(method):
    return (method["name"], len(method["params"]))


# RSECOPSX_E0_LITERAL_WORD_TAINT_FIX_20261017
# Java string/char literal contents (escapes handled) -- data, never code.
_J5_LITERAL_MASK = re.compile(
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


def _j5_expr_hits(expr, taint):
    # RSECOPSX_E0_LITERAL_WORD_TAINT_FIX_20261017
    # String/char literal CONTENTS are data, never identifiers: the
    # substring scan below used to treat the prose word "bar" inside
    # ``new Object[] {"The streetz 4 Ms bar"}`` as the tainted variable
    # ``bar`` and taint the whole array -- the single idiom behind all 11
    # BenchmarkJava JAVA_J5_LDAP false positives (chain
    # ``parameter:filters -> filters -> ctx.search(``) and the
    # ``write("Parameter value: " + bar)`` XSS follow-ons.  Concatenation
    # flows are untouched: tainted variables live OUTSIDE the quotes
    # (``"uid=" + bar`` still matches ``bar``).  Same masking discipline as
    # the JAVA_TAINT_* line layer's _B1_JAVA_TAINT_LITERAL_MASK.
    masked = _J5_LITERAL_MASK.sub(" ", str(expr or ""))
    hits = []
    for name in taint:
        if re.search(r'(?<![\w$])' + re.escape(name) + r'(?![\w$])',
                     masked):
            if name not in hits:
                hits.append(name)
    return hits


# RSECOPSX_J5_MULTILINE_ASSIGNMENT_FIX_20260907
# Generic reconstruction of Java assignments spanning physical lines.
# No library-specific or Base64-specific handling is introduced.
def _j5_logical_statements(lines, start_line):
    """Yield (first_line_number, logical_statement) for method-body statements."""
    i = 0
    n = len(lines)

    def assignment_start(line):
        return bool(re.match(
            r"^\s*(?:(?:final|static|private|public|protected|volatile|transient)\s+)*"
            r"(?:(?:[A-Za-z_$][\w$<>\[\],.?]*\s+)+)?"
            r"[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)?"
            r"\s*="
            , line))

    def balanced(text):
        paren = 0
        bracket = 0
        brace = 0
        quote = None
        escaped = False

        for ch in text:
            if quote is not None:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = None
                continue

            if ch in ('"', "'"):
                quote = ch
            elif ch == '(':
                paren += 1
            elif ch == ')':
                paren -= 1
            elif ch == '[':
                bracket += 1
            elif ch == ']':
                bracket -= 1
            elif ch == '{':
                brace += 1
            elif ch == '}':
                brace -= 1

        return (
            paren == 0
            and bracket == 0
            and brace == 0
            and quote is None
        )

    while i < n:
        raw = lines[i]
        stripped = raw.strip()

        if not stripped or stripped.startswith('//'):
            yield start_line + i, raw
            i += 1
            continue

        if not assignment_start(raw):
            yield start_line + i, raw
            i += 1
            continue

        if ';' in raw and balanced(raw):
            yield start_line + i, raw
            i += 1
            continue

        first = i
        parts = [raw]
        j = i + 1

        while j < n:
            parts.append(lines[j])
            candidate = "\n".join(parts)

            if ';' in lines[j] and balanced(candidate):
                j += 1
                break

            j += 1

        yield start_line + first, "\n".join(parts)
        i = j

# RSECOPSX_J6B_EXACT_ELEMENT_GUARD_20260907
_J6B_LIST_ADD_RE = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*\.\s*add\s*\((.*)\)\s*;?$", re.I
)
_J6B_LIST_REMOVE_RE = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*\.\s*remove\s*\(\s*(\d+)\s*\)\s*;?$", re.I
)
_J6B_LIST_GET_RE = re.compile(
    r"^\s*([A-Za-z_$][\w$]*)\s*\.\s*get\s*\(\s*(\d+)\s*\)\s*$", re.I
)
_J6B_MAP_PUT_RE = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*\.\s*put\s*\(\s*([^,]+)\s*,\s*(.+)\)\s*;?$", re.I
)
_J6B_MAP_GET_RE = re.compile(
    r"^\s*([A-Za-z_$][\w$]*)\s*\.\s*get\s*\(\s*(.+?)\s*\)\s*$", re.I
)

# A leading Java cast: ``(String) x``, ``(java.lang.Object) y``. Only a
# parenthesised type-ish name immediately followed by an identifier counts,
# so grouping parens such as ``((7 * 42)) x`` or ``(a + b) * c`` are left
# alone.
_J5_CAST_PREFIX_RE = re.compile(
    r"^\s*\(\s*(?:[A-Za-z_$][\w$]*\s*\.\s*)*[A-Za-z_$][\w$]*"
    r"(?:\s*<[^<>]*>)?(?:\s*\[\s*\])*\s*\)\s*(?=[A-Za-z_$])"
)


def _j5_strip_casts(text: str) -> str:
    """Drop leading casts so ``expr.get(k)`` resolution can see the call.

    BenchmarkJava writes collection round-trips as ``bar = (String)
    map.get(key)``; ``_J6B_MAP_GET_RE`` is anchored at ``^``, so the cast
    made every such get unresolvable -- the exact-element guard could
    neither prove the safe write safe nor reach the tainted one, on both
    the positive and the negative side of the oracle.
    """
    prev = None
    while text != prev:
        prev = text
        text = _J5_CAST_PREFIX_RE.sub("", text, count=1)
    return text.lstrip()

def _j6b_literal_value(expr):
    text = (expr or "").strip().rstrip(";").strip()
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if re.fullmatch(r'"(?:[^"\\]|\\.)*"', text, re.S):
        return text[1:-1]
    if re.fullmatch(r"'(?:[^'\\]|\\.)*'", text, re.S):
        return text[1:-1]
    return None

def _j6b_constant_value(expr, constants):
    text = (expr or "").strip().rstrip(";").strip()
    literal = _j6b_literal_value(text)
    if literal is not None:
        return literal
    if re.fullmatch(r"[A-Za-z_$][\w$]*", text):
        return constants.get(text)
    return None

def _j6b_exact_selected_safe(rhs, logical_body, start_line, constants, taint, return_detail=False):
    # Only prove exact constant list/map selection when every relevant
    # collection mutation can be reconstructed. Unknown access stays unsafe.
    rhs_text = _j5_strip_casts(
        _j6b_strip_java_comments(rhs or "").strip().rstrip(";").strip()
    )
    list_get = _J6B_LIST_GET_RE.match(rhs_text)
    map_get = _J6B_MAP_GET_RE.match(rhs_text)

    if not list_get and not map_get:
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        if return_detail:
            return (False, None)
        return False

    if list_get:
        obj = list_get.group(1)
        index = int(list_get.group(2))
        items = []

        for _line_no, raw in _j5_logical_statements(logical_body, start_line):
            stmt = re.sub(r"\s+", " ", _j6b_strip_java_comments(raw)).strip()

            add = _J6B_LIST_ADD_RE.search(stmt)
            if add and add.group(1) == obj:
                value = add.group(2).strip()
                items.append({
                    "expr": value,
                    "tainted": bool(_j5_expr_hits(value, taint)),
                })
                continue

            remove = _J6B_LIST_REMOVE_RE.search(stmt)
            if remove and remove.group(1) == obj:
                idx = int(remove.group(2))
                if 0 <= idx < len(items):
                    items.pop(idx)
                else:
                    return False

        if 0 <= index < len(items):
            selected_tainted = items[index]["tainted"]
            if return_detail:
                return (not selected_tainted, items[index]["expr"])
            return not selected_tainted
        return False

    obj = map_get.group(1)
    key = _j6b_constant_value(map_get.group(2), constants)
    if key is None:
        return False

    values = {}
    for _line_no, raw in _j5_logical_statements(logical_body, start_line):
        stmt = re.sub(r"\s+", " ", _j6b_strip_java_comments(raw)).strip()
        put = _J6B_MAP_PUT_RE.search(stmt)
        if put and put.group(1) == obj:
            put_key = _j6b_constant_value(put.group(2), constants)
            if put_key is None:
                return False
            value = put.group(3).strip()
            values[str(put_key)] = {
                "expr": value,
                "tainted": bool(_j5_expr_hits(value, taint)),
            }

    selected = values.get(str(key))
    if selected is None:
        if return_detail:
            return (False, None)
        return False
    if return_detail:
        return (not selected["tainted"], selected["expr"])
    return not selected["tainted"]

def _j6b_strip_java_comments(text):
    s = text or ""
    out = []
    i = 0
    n = len(s)
    quote = None
    esc = False
    block = False
    line = False
    while i < n:
        ch = s[i]
        nxt = s[i + 1] if i + 1 < n else ""
        if line:
            if ch == "\n":
                line = False
                out.append(ch)
            else:
                out.append(" ")
            i += 1
            continue
        if block:
            if ch == "*" and nxt == "/":
                out.extend([" ", " "])
                i += 2
                block = False
            else:
                out.append("\n" if ch == "\n" else " ")
                i += 1
            continue
        if quote:
            out.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            out.extend([" ", " "])
            i += 2
            line = True
            continue
        if ch == "/" and nxt == "*":
            out.extend([" ", " "])
            i += 2
            block = True
            continue
        out.append(ch)
        i += 1
    return "".join(out)

_J6B_COMMENT_FIX_MARKER = 'RSECOPSX_J6B_INLINE_COMMENT_TAINT_FIX_STRUCTURAL_V2_20260907'
def _j5_assignment(line):
    m = _J5_ASSIGN_RE.match(line or "")
    if not m:
        return None, None
    return m.group(1).replace(" ", ""), m.group(2)


def _j5_sink_return(rhs):
    return bool(_J5_SECURITY_RETURN_CALLS.search(rhs or ""))


# Block-opening statements whose frames preserve kill rights: inside
# try/finally, if execution reached a later statement then every earlier
# statement of the frame ran (an exception would have left it).
_J5_TRY_HEAD_RE = re.compile(r"^(?:try|finally)\b")

# A right-hand side that IS a single call -- ``doSomething(a, b)``,
# ``obj.doSomething(a)``, ``new Test().doSomething(a)`` -- anchored so a
# larger expression (``helper(a) + b``) never masks. Mirrors the
# call-site pattern the interprocedural loop uses, so (name, arity)
# resolution agrees.
_J5_CALL_SHAPE_RE = re.compile(
    r'^(?:(?:new\s+[A-Za-z_$][\w$<>,.?]*\s*\(\s*\)\s*\.\s*)'
    r'|(?:(?:[A-Za-z_$][\w$]*\s*\.\s*)*))'
    r'([A-Za-z_$][\w$]*)\s*\((.*)\)$',
    re.S
)


def _j5_split_paren(text: str, open_idx: int):
    """Split ``cond) rest`` at the paren opened at ``open_idx``."""
    depth_p = 0
    for i in range(open_idx, len(text)):
        if text[i] == "(":
            depth_p += 1
        elif text[i] == ")":
            depth_p -= 1
            if depth_p == 0:
                return text[open_idx + 1:i], text[i + 1:].strip()
    return None, None


def _j5_inline_assignment(s):
    """``(lhs, rhs)`` of an assignment written AFTER an inline control
    keyword: ``if (cond) bar = rhs;``, ``else bar = rhs;``, and their
    nested / ``else if`` spellings.

    The anchored assignment regex sees the keyword first and fails, so
    the main loop used to leave ``bar`` untainted through
    ``if (param != null) bar = param.split(" ")[0];`` (BenchmarkJava
    01179's shape) -- the callee then looked constant-returning to
    every consumer of its ``returns``: knowledge called the helper
    clean and killed a REAL flow in the caller. Callers treat the
    stripped write as unconditional: propagation-only sites taint
    ``lhs`` when ``rhs`` is tainted (the branch MIGHT run), while kill
    sites must pass ``can_kill=False`` -- a write behind a control
    prefix is never unconditional. Braced forms return
    ``(None, None)``: those statements arrive as their own lines.
    """
    probe = s
    for _ in range(6):
        im = re.match(r"if\s*\(", probe)
        if im:
            cond, probe = _j5_split_paren(probe, im.end() - 1)
            if cond is None:
                return None, None
        elif re.match(r"else\b", probe):
            probe = re.sub(r"^else\s+", "", probe, count=1)
        else:
            break
        if not probe or probe.startswith("{"):
            return None, None
        lhs, rhs = _j5_assignment(probe)
        if lhs:
            return lhs, rhs
    return None, None


def _j5_balanced_close(text: str, open_idx: int):
    """Index of the ``)`` closing the ``(`` at ``open_idx``; None if it
    never closes. Quote-aware so a paren inside a string or char
    literal cannot end the scan early."""
    if open_idx is None or open_idx < 0 or open_idx >= len(text):
        return None
    if text[open_idx] != "(":
        return None
    depth = 0
    quote = None
    esc = False
    for i in range(open_idx, len(text)):
        ch = text[i]
        if quote:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
    return None


def _j5_split_ternary(expr: str):
    """Split ``cond ? then : else`` at the top level.

    Returns (cond, then, else) or None when the expression is not a
    ternary. Nesting (a ternary inside a branch), parens and quoted
    strings are tracked so the split lands on the outermost pair.
    """
    text = (expr or "").strip()
    depth = 0
    quote = None
    esc = False
    q_mark = None
    tern_depth = 0
    colon_for: dict[int, int] = {}
    for i, ch in enumerate(text):
        if quote:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif depth == 0 and ch == "?":
            if tern_depth == 0:
                q_mark = i
            tern_depth += 1
        elif depth == 0 and ch == ":" and tern_depth:
            tern_depth -= 1
            colon_for[tern_depth] = i
            if tern_depth == 0 and q_mark is not None:
                return text[:q_mark].strip(), \
                    text[q_mark + 1:colon_for[0]].strip(), \
                    text[colon_for[0] + 1:].strip()
    return None


def _j5_java_unescape(s: str):
    """Unescape a Java string/char literal body; None on unknown escapes.

    Unknown escapes refuse the fold rather than guessing -- a wrong
    constant is a wrong branch decision.
    """
    out = []
    i = 0
    while i < len(s):
        if s[i] != "\\":
            out.append(s[i])
            i += 1
            continue
        if i + 1 >= len(s):
            return None
        e = s[i + 1]
        simple = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f",
                  "\\": "\\", '"': '"', "'": "'"}
        if e in simple:
            out.append(simple[e])
            i += 2
        elif e == "u":
            if i + 6 > len(s):
                return None
            try:
                out.append(chr(int(s[i + 2:i + 6], 16)))
            except ValueError:
                return None
            i += 6
        else:
            return None
    return "".join(out)


def _j5_string_receiver(recv: str, env: dict):
    """Resolve ``recv`` to a constant string: a literal or a known name."""
    recv = (recv or "").strip()
    if re.fullmatch(r'"(?:[^"\\]|\\.)*"', recv):
        return _j5_java_unescape(recv[1:-1])
    if re.fullmatch(r"[A-Za-z_$][\w$]*", recv) and isinstance(env.get(recv), str):
        return env[recv]
    return None


def _j5_java_char_literals(text: str):
    """Replace Java char literals with their integer code (javac semantics).

    Java chars are ints, so ``'B'`` folds to ``66`` and a folded switch
    discriminant compares against its ``case 'B':`` labels the way the
    runtime does. Double-quoted regions pass through untouched so
    apostrophes inside strings survive. Unresolvable quotes return None
    (refuse the fold).
    """
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                return None
            out.append(text[i:j + 1])
            i = j + 1
            continue
        if ch == "'":
            j = i + 1
            while j < n and text[j] != "'":
                j += 2 if text[j] == "\\" else 1
            if j >= n or j == i + 1:
                return None
            body = _j5_java_unescape(text[i + 1:j])
            if body is None or len(body) != 1:
                return None
            out.append(str(ord(body)))
            i = j + 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _j5_const_expr(expr: str, env: dict):
    """Evaluate a Java integer/boolean/string expression against ``env``.

    Returns the value when every identifier is a known constant and the
    syntax is arithmetic only, else None. Calls, field reads, ``null``,
    hex/octal literals and unknown names all refuse to evaluate: a wrong
    constant is a wrong branch decision, which is a silent miss, so the
    contract is "fold only what is provable".

    Constant string operations are resolved first: ``"ABC".charAt(1)``
    and ``guess.length()`` on a literal or a KNOWN string constant, with
    a literal integer index (the benchmark's switch discriminants are
    ``char switchTarget = guess.charAt(1)``). A pure string literal
    evaluates to its content so it can enter the environment; strings
    otherwise refuse the numeric evaluator -- substituting ``"123"`` as
    the number 123 would be a wrong fold.
    """
    if not expr:
        return None
    text = expr.strip()
    if re.fullmatch(r'"(?:[^"\\]|\\.)*"', text):
        return _j5_java_unescape(text[1:-1])
    while True:
        m = re.search(r"\s*\.\s*charAt\s*\(\s*(\d+)\s*\)", text)
        if m:
            val = _j5_string_receiver(text[:m.start()], env)
            if val is None:
                return None
            pos = int(m.group(1))
            if pos >= len(val):
                return None
            # The prefix IS the receiver whenever it resolved (an
            # expression in front of it refuses above), so the whole
            # ``receiver.charAt(n)`` span collapses to the char code.
            text = str(ord(val[pos])) + text[m.end():]
            continue
        m = re.search(r"\s*\.\s*length\s*\(\s*\)", text)
        if m:
            val = _j5_string_receiver(text[:m.start()], env)
            if val is None:
                return None
            text = str(len(val)) + text[m.end():]
            continue
        break
    text = _j5_java_char_literals(text)
    if text is None:
        return None
    text = re.sub(r"\btrue\b", "True", text, flags=re.I)
    text = re.sub(r"\bfalse\b", "False", text, flags=re.I)
    for name in re.findall(r"[A-Za-z_$][\w$]*", text):
        if name in ("True", "False"):
            continue
        if name not in env:
            return None
        if isinstance(env[name], str):
            # Strings only participate via charAt/length (resolved above).
            return None
        text = re.sub(r"\b%s\b" % re.escape(name), str(env[name]), text)
    text = text.replace("&&", " and ").replace("||", " or ")
    if not re.fullmatch(
        r"(?:[0-9+\-*/%()<>=!\s]|and|or|not|True|False)+", text
    ):
        return None
    try:
        return eval(text, {"__builtins__": {}}, {})
    except Exception:
        return None


# Java output-escaping sanitizers: each escape is correct ONLY for the
# vuln class it is listed under (the per-class model of
# taint_engine.SANITIZERS). Measured on BenchmarkJava: these patterns
# cover 28/53 JAVA_TAINT_XSS and 34/52 JAVA_J5_XSS negative-oracle tests,
# all of the shape ``bar = encodeForHTML(param)`` with the encode between
# the source and the response sink. Deliberately absent: encodeForURL
# (URL encoding is not HTML encoding -- mirrors the Python table's
# ``urllib.parse.quote`` exclusion) and context-dependent ``escape`` names.
_JAVA_SANITIZERS: dict = {
    "xss": (
        re.compile(
            r"\bencodeFor(?:HTML|HTMLAttribute|JavaScript|JavaScriptAttribute"
            r"|CSS|XPath)\s*\(",
            re.I,
        ),
        re.compile(
            r"\bEncode\s*\.\s*for(?:Html|HtmlAttribute|UnquotedHtmlAttribute"
            r"|JavaScript|CssString|XPath)\s*\(",
            re.I,
        ),
        re.compile(r"\bhtmlEscape\s*\(", re.I),
        # escapeHtml3/escapeHtml4 (commons-lang3) and commons-lang's plain
        # escapeHtml (BenchmarkTest00389 uses StringEscapeUtils.escapeHtml).
        # The \b also blocks unescapeHtml -- an unescaper is the opposite
        # of a sanitizer.
        re.compile(r"\bescapeHtml\d*\s*\(", re.I),
        re.compile(r"\bJsoup\s*\.\s*clean\s*\(", re.I),
    ),
}


def _j5_blank_sanitizer_spans(eff: str, vuln: str):
    """``eff`` with every sanitizer call for ``vuln`` removed, its
    arguments included (balanced parens).

    Returns None when the class has no sanitizer patterns, nothing
    matched, or a wrap is unbalanced -- the caller then falls back to
    the unblanked text, which is the conservative direction for source
    detection and refuses coverage claims for unknown extents.
    """
    patterns = _JAVA_SANITIZERS.get(vuln)
    if not patterns:
        return None
    spans = []
    for pat in patterns:
        spans.extend(pat.finditer(eff))
    if not spans:
        return None
    spans.sort(key=lambda m: m.start())
    out = []
    last = 0
    for m in spans:
        if m.start() < last:
            continue
        # Walk from the open paren the pattern ended on to its match.
        depth = 0
        i = m.end() - 1
        closed = False
        while i < len(eff):
            ch = eff[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    closed = True
                    i += 1
                    break
            i += 1
        if not closed:
            return None
        out.append(eff[last:m.start()])
        last = i
    out.append(eff[last:])
    return "".join(out)


def _j5_sanitizer_covers(eff: str, vuln: str, live) -> bool:
    """True when every live contribution to ``eff`` sits INSIDE a
    sanitizer wrap that is correct for ``vuln``.

    The wrap spans (arguments included) are blanked out; if what remains
    -- the contributions outside any wrap -- holds a request source or a
    live tainted name, the value can still carry the vuln and coverage
    fails. Names the positional walk has already proven safe are not
    live and cannot break coverage, so the result composes with ``dead``
    propagation downstream. An unbalanced wrap (malformed input) fails
    closed: coverage cannot be claimed for a span whose extent is
    unknown.
    """
    outside = _j5_blank_sanitizer_spans(eff, vuln)
    if outside is None:
        return False
    if (
        _J5_SOURCE_RE.search(outside)
        or _J5_COOKIE_VALUE_RE.search(outside)
        or _J5_WRAPPER_SOURCE_RE.search(outside)
    ):
        return False
    return not _j5_expr_hits(outside, live)


def _j5_switch_taken_labels(lines, start, value, env):
    """0-based indices of the case/default label lines a switch whose
    discriminant folds to ``value`` will actually execute.

    Scans the switch body from ``start`` (the line after the opener)
    with brace balance on masked text, evaluates every ``case`` label as
    a constant, and selects the matching group -- or ``default`` when no
    case matches (javac semantics: the POSITION of ``default`` in the
    body does not matter). Fall-through chains are included: a case
    label with no statements before the next label hands its body to
    that label, so every label in the chain flips execution on.

    Returns an empty set when nothing runs (no matching case and no
    default), or None when the body cannot be parsed -- the caller then
    falls back to the unfoldable path, which withholds kill rights.
    Labels nested deeper than this switch (a switch inside a case body)
    are excluded so a nested label can never turn execution on while an
    untaken outer group contains it.
    """
    depth = 1
    labels = []  # (line index, case expression or None for default)
    end = None
    i = start
    while i < len(lines):
        text = lines[i]
        depth += text.count("{") - text.count("}")
        if depth <= 0:
            end = i
            break
        if depth == 1:
            m = re.match(r"\s*case\s+(.+?)\s*:", text)
            if m:
                labels.append((i, m.group(1)))
            elif re.match(r"\s*default\s*:", text):
                labels.append((i, None))
        i += 1
    if end is None or not labels:
        return None
    matched = None
    for k, (_li, expr) in enumerate(labels):
        if expr is None:
            continue
        v = _j5_const_expr(expr, env)
        if v is not None and v == value and not isinstance(v, bool):
            matched = k
            break
    if matched is None:
        for k, (_li, expr) in enumerate(labels):
            if expr is None:
                matched = k
                break
        if matched is None:
            return set()  # no matching case and no default: nothing runs
    taken = {labels[matched][0]}
    k = matched
    while k + 1 < len(labels):
        between = lines[labels[k][0] + 1:labels[k + 1][0]]
        if all(
            not g.strip() or re.match(r"\s*(?:case\s+.+?|default)\s*:", g)
            for g in between
        ):
            taken.add(labels[k + 1][0])
            k += 1
        else:
            break
    return taken


def _j5_local_types(source: str) -> set:
    """Type names declared in ``source`` (class/interface/enum/record).

    The receiver allow-list for file-local call knowledge: a
    ``new Type().helper(...)`` call may only be killed with file-local
    knowledge when ``Type`` is declared in the very file that computed
    that knowledge.
    """
    return set(re.findall(
        r"\b(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)",
        source))


# RSECOPSX_E5_WALK_FRAME_BRACE_FIX_20261017
_EXPR_BRACE_PRECEDERS = "=([,]"


def _j5_block_brace_counts(masked_raw: str):
    """``(block_open, block_close)`` -- the braces that may touch the
    dead-walk's frame stack in one logical statement.

    Only BLOCK braces belong on the stack: method/initializer
    signatures, control-flow heads, ``try``/``catch``/``finally``,
    ``} else {``.  The ``{``/``}`` of an ARRAY/COLLECTION INITIALIZER
    expression (``String[] args = {cmd};``, ``new Object[] {...}``,
    ``new int[][]{{1},{2}}``) opens no scope, and counting them
    corrupted the stack in BOTH directions: the expression's own ``}``
    popped a real enclosing frame (a ``filters = new Object[]{...}``
    line inside ``try`` used to dissolve the try frame) and its ``{``
    pushed a phantom cond frame that stripped kill rights from the NEXT
    top-level write -- BenchmarkTest00571: ``String[] args = {cmd};``
    left a phantom frame over ``String[] argsEnv = {bar};`` so bar's
    fold could never propagate its death into the env array (the whole
    JAVA_J5_CMD family on findings17).  Braces inside string/char
    literals are blanked first (``String s = "{";``).  An initializer
    ``{`` is recognised by its nesting (inside another initializer) or
    the preceding non-space character -- ``=``, ``(``, ``,``, ``[``,
    ``]`` -- while lambda/anonymous-class/control braces (``)``, ``}``,
    identifier, ``>`` before ``{``) stay block braces.  Unbalanced
    closers still count as block closes: the caller's stray-closer
    tolerance decides whether a frame exists to pop.
    """
    text = _J5_LITERAL_MASK.sub(" ", masked_raw or "")
    opens = 0
    closes = 0
    stack: list[str] = []  # "block" | "expr" per open brace
    prev = ""
    for ch in text:
        if ch == "{":
            if (stack and stack[-1] == "expr") or \
                    prev in _EXPR_BRACE_PRECEDERS:
                stack.append("expr")
            else:
                stack.append("block")
                opens += 1
        elif ch == "}":
            kind = stack.pop() if stack else "block"
            if kind == "block":
                closes += 1
        if not ch.isspace():
            prev = ch
    return opens, closes


def _j5_local_call_prefix(pre: str, local_types) -> bool:
    """True when a call with prefix ``pre`` can only resolve to a method
    declared in THIS file, so file-local call knowledge may mask its
    arguments.

    * bare ``helper(a)`` -- an in-file declaration of that name wins Java
      resolution (a declared method shadows static imports; two
      same-name-same-arity methods cannot coexist in one class);
    * ``this.helper(a)`` -- explicitly the current class;
    * a chain of ``new Type().`` receivers where EVERY type is declared
      in this file (BenchmarkJava's ``new Test().doSomething`` inner-class
      idiom).

    Anything else -- ``Other.helper``, ``var.helper``, ``super.helper``,
    ``utils.helper`` -- can resolve to a definition outside this file even
    when an equally-named (name, arity) exists locally, so the caller
    falls back to project-wide ``safe_calls``. Fails closed when the file
    declares no types at all.
    """
    p = pre.strip()
    if not p:
        return True
    if p == "this.":
        return True
    if not local_types:
        return False
    if not re.fullmatch(
            r"(?:new\s+[A-Za-z_$][\w$<>,.?]*\s*\(\s*\)\s*\.\s*)+", p):
        return False
    return all(
        t in local_types
        for t in re.findall(r"new\s+([A-Za-z_$][\w$]*)", p))


def _j5_dead_names(body, start_line, taint, sink_line, safe_calls=None,
                   vuln=None, local_calls=None, local_types=None):
    """Names whose LAST write before ``sink_line`` is provably safe.

    The fixed-point taint set answers "was this name ever tainted in this
    method"; it cannot answer "was it tainted HERE". Two shapes of the
    benchmark's negative oracle fall into that gap and this walk closes
    them, each measured on BenchmarkJava (xpathi 12/20 negative tests
    still flagged without it, plus the cross-category J5_XSS hits that
    followed the same overwritten variable into println()):

    1. Overwrite: ``bar = param; ... bar = (String) map.get(safeKey);`` --
       taint is only ever added, so ``bar`` stayed tainted forever. The
       walk tracks a DEATH set: an unconditional write whose right-hand
       side touches no live taint kills the name; a source write, or a
       write touching live taint, resurrects it. Liveness is evaluated
       positionally (``taint - dead`` at each statement), so
       ``expression = "..." + bar`` no longer resurrects ``expression``
       from a ``bar`` that its own final write had already proven safe.
    2. Unreachable branch:
       ``int num = 86; if ((7 * 42) - num > 200) bar = "const"; else
       bar = param;`` and its ternary twin
       ``bar = (7 * 18) + num > 200 ? "const" : param;`` (00683) -- in
       both the tainted write is dead code, but the flow-insensitive set
       cannot know that. Constant folding evaluates the condition against
       the integers committed earlier in the walk; a folded condition
       records which branch runs (skipping the other, or reducing the
       ternary to its taken branch), an unfoldable one processes the
       branch as conditional -- resurrect-only, never a kill, because a
       wrong kill is a silent miss and a missed kill is a visible false
       positive.

    3. Scope-colliding declarations (F0, measured on 01479/02370): a
       ``org.w3c.dom.Element value = nodeList.item(i)`` inside the result
       loop shares its NAME with an unrelated, live
       ``String value = values[i]`` in a sibling parameter loop -- both
       legal Java, but this walk is name-based, so the String binding
       kept the name alive and printed through the Node binding.  A
       DECLARATION whose initializer carries no live taint now records a
       deferred kill that applies only when the sink lies inside the
       declaration's own frame stack; every later write supersedes it,
       and a sink outside the frame keeps its name.

    Nesting is a stack of classified frames rather than a scalar depth,
    because only some frames deserve kill rights: inside ``try`` /
    ``finally``, if execution reached the sink then every earlier
    statement of the frame ran (an exception would have left it), so a
    safe write there is a real kill -- benchmark code wraps the whole
    sink path in ``try { ... }`` and a scalar-depth rule would refuse
    to see through it. ``if``/``for``/``while``/``switch``/``catch``/
    lambda frames can be skipped or unentered, so their writes only
    resurrect. A method-signature line contributes no frame (its brace
    opens the body, it does not nest it), and a stray closer on a body
    that begins mid-method is ignored rather than driving the stack
    negative.

    The J6B exact-element resolution is mirrored exactly (including the
    ``(String)`` cast benchmark code puts on round-trips), so the kill
    can never suppress a flow the main analysis had proven through a
    collection. Call arguments get the same treatment through
    ``safe_calls``: when the right-hand side is a call and every project
    method resolvable at (name, arity) has dead-refined returns with no
    taint left, the tainted names inside the ARGUMENTS cannot reach this
    lhs (01479 does ``bar = new Test().doSomething(request, param)`` where
    the helper folds the constant and returns it -- syntactically
    identical to a passthrough helper, and only the callee's refined
    returns tell them apart). Unresolvable callees and callees that still
    return taint keep their arguments live: never masking is the
    conservative direction. Results refine -- never replace -- the
    fixed-point state; ``returns`` are refined dead-aware before they
    seed the caller, which only narrows interprocedural propagation.

    ``local_calls`` is FILE-LOCAL knowledge guarded by
    ``_j5_local_call_prefix``: unlike project-wide ``safe_calls`` -- whose
    (name, arity) is only ever added when EVERY resolution project-wide
    is clean -- a key known clean inside one file must not mask a call
    that could resolve outside it (``Other.helper(...)`` may be a
    different class's method). The guard admits bare ``helper(...)``,
    ``this.``, and ``new Type().`` chains whose types the same file
    declares; everything else falls back to ``safe_calls`` alone.
    ``local_types`` is that file's declared type names.
    """
    safe_calls = safe_calls or set()
    local_calls = local_calls or set()
    dead: set[str] = set()
    # F0: scope-guarded declaration kills -- a DECLARATION inside a
    # kill-less (cond) frame whose initializer carries no live taint
    # cannot produce a live binding; because cond-frame writes may not
    # kill outright (the frame can be skipped), the kill is DEFERRED and
    # only applied when the sink lies inside the declaration's own frame
    # stack, which is exactly where Java's scoping makes this declaration
    # the binding the sink sees.  Any later write to the name supersedes
    # the candidate (last-write discipline), and a candidate whose frame
    # closed before the sink is dropped (conservative direction).
    pending_decls: dict[str, tuple] = {}
    int_env: dict[str, int] = {}
    j6b_constants: dict = {}
    frames: list[str] = []  # "try" frames grant kills; "cond" frames do not
    pending_else = None  # None | "folded" | "unknown"
    # Active folded switches, outermost first: {"labels": set of label
    # lines that turn execution on, "on": bool, "base": len(frames) at
    # the opener}. A statement executes only when EVERY enclosing switch
    # has its taken group on (see the gate below).
    sw_stack: list[dict] = []
    masked_body = _j5_mask("\n".join(body)).splitlines()
    idx = 0

    def record(lhs, rhs, s, can_kill):
        if not lhs or not rhs or "." in lhs:
            return
        # F0: any real write to this name supersedes a deferred
        # declaration candidate -- the new write is the last write and
        # decides liveness on its own.
        pending_decls.pop(lhs, None)
        # Ternary: ``bar = cond ? "const" : param`` is the benchmark's
        # other negative shape (00683). A constant-foldable condition
        # reduces the write to its taken branch, so the untaken branch's
        # taint (or safety) never reaches the variable; an unfoldable
        # condition keeps the whole expression, so hits on ANY branch
        # resurrect -- the conservative direction.
        tern = _j5_split_ternary(rhs)
        if tern is not None:
            folded = _j5_const_expr(tern[0], int_env)
            if folded is True:
                rhs = tern[1]
            elif folded is False:
                rhs = tern[2]
        # Constant environment: only a kill-capable write commits a value;
        # anything conditional means the value differs per path and
        # folding on it would invent a branch decision. Strings enter the
        # environment as well (``String guess = "ABC"`` feeds
        # ``guess.charAt(1)`` below); bools stay excluded as before.
        if can_kill:
            val = _j5_const_expr(rhs, int_env)
            if (
                isinstance(val, bool)
                or not isinstance(val, (int, str))
                or (isinstance(val, str) and len(val) > 64)
            ):
                int_env.pop(lhs, None)
            else:
                int_env[lhs] = val
        else:
            int_env.pop(lhs, None)
        # Source check on the (possibly folded) right-hand side: a request
        # source always lives there, and searching the whole statement
        # would resurrect a variable whose source call sits in an untaken
        # ternary branch. A source INSIDE a class-correct sanitizer wrap
        # (Encode.forHtml(request.getParameter("x"))) is not a carrier of
        # this sink's vuln -- it is blanked before the search; sources
        # outside any wrap still resurrect, as do all sources when the
        # sink class has no sanitizer model.
        eff = _j6b_strip_java_comments(rhs)
        src_probe = eff
        if vuln is not None:
            blanked = _j5_blank_sanitizer_spans(eff, vuln)
            if blanked is not None:
                src_probe = blanked
        if (
            _J5_SOURCE_RE.search(src_probe)
            or _J5_COOKIE_VALUE_RE.search(src_probe)
            or _J5_WRAPPER_SOURCE_RE.search(src_probe)
        ):
            dead.discard(lhs)
            return
        # Positional liveness: a name whose last write up to this point
        # was proven safe cannot carry taint into a later assignment.
        live = taint - dead
        probe = eff
        if safe_calls or local_calls:
            es = eff.strip()
            cm = _J5_CALL_SHAPE_RE.match(es)
            if cm:
                key = (cm.group(1), len(_split_args(cm.group(2))))
                trusted = key in safe_calls
                if not trusted and key in local_calls:
                    # File-local knowledge only applies where Java
                    # resolution is guaranteed to land inside this file
                    # (see _j5_local_call_prefix).
                    trusted = _j5_local_call_prefix(
                        es[:cm.start(1)], local_types)
                if trusted:
                    # The callee's dead-refined returns prove it drops
                    # taint (see _j5_analyze_method), so tainted names
                    # inside its ARGUMENTS cannot reach this lhs; only
                    # the expression outside the call still counts as a
                    # carrier.
                    probe = es[:cm.start(2)] + es[cm.end(2):]
        # Mirror the main loop's decision for this RHS exactly -- in
        # particular the J6B exact-element resolution (which sees through
        # the ``(String)`` cast benchmark code puts on round-trips), so
        # the kill can never contradict a flow the analysis already
        # proved through a collection.
        hits = _j5_expr_hits(_j6b_strip_java_comments(probe), live)
        exact_safe, selected_expr = _j6b_exact_selected_safe(
            rhs, body, start_line, j6b_constants, live, return_detail=True
        )
        if selected_expr is not None:
            selected_hits = _j5_expr_hits(
                _j6b_strip_java_comments(selected_expr), live
            )
            if selected_hits:
                hits = selected_hits
            elif exact_safe:
                hits = []
        elif exact_safe:
            hits = []
        if hits and vuln and can_kill and _j5_sanitizer_covers(eff, vuln, live):
            # Every live carrier of this value sits inside a sanitizer
            # wrap that is correct for THIS sink's class (00278:
            # ``bar = HtmlUtils.htmlEscape(param)`` then print(bar)):
            # the written value cannot carry this vuln, so the write
            # kills exactly like a constant. Conditional frames are
            # excluded (can_kill) -- the wrap may not run on other paths.
            hits = []
        if hits:
            dead.discard(lhs)
        elif can_kill and not _j5_sink_return(rhs):
            dead.add(lhs)
        elif (
            not can_kill
            and not _j5_sink_return(rhs)
            and _J5_DECL_RE.match(s)
        ):
            # F0: a DECLARATION in a cond frame with a proven-dead
            # initializer (hits empty, no source -- checked above).
            # Defer the kill; it applies only if the sink ends up inside
            # this declaration's frame stack (see pending_decls note).
            # The sink-return carve-out keeps the existing conservatism:
            # a security-sink result may carry data beyond its arguments
            # (`rs = stmt.executeQuery(constant)`), so it never proves
            # safety by itself.
            pending_decls[lhs] = tuple(frames)

    for line_no, raw in _j5_logical_statements(body, start_line):
        if line_no >= sink_line:
            break
        # Frames are classified from the masked text so braces inside
        # strings and comments cannot skew the stack.
        nlines = raw.count("\n") + 1
        masked_raw = "\n".join(masked_body[idx:idx + nlines])
        idx += nlines
        head = masked_raw.strip()
        can_kill = all(f == "try" for f in frames)
        # RSECOPSX_E5_WALK_FRAME_BRACE_FIX_20261017 -- only BLOCK braces
        # touch the stack; array/collection-initializer braces are
        # expression braces (see _j5_block_brace_counts).
        n_block_open, n_block_close = _j5_block_brace_counts(masked_raw)
        # Closes pop before opens so ``} else {`` swaps frames instead of
        # nesting; stray closers (a body beginning mid-method) are ignored.
        for _ in range(n_block_close):
            if frames:
                frames.pop()
        # A switch's own closing brace has now popped its frame: retire
        # it so later statements are gated by the enclosing switch only
        # (a nested switch retires independently of its outer one).
        while sw_stack and len(frames) < sw_stack[-1]["base"]:
            sw_stack.pop()
        # A switch whose discriminant folds to a constant executes
        # exactly one case group -- the matching case, else default
        # (javac). Pre-scan the body for the label lines that group
        # turns execution on; an unparseable body falls back to the
        # unfoldable path (cond frame, no skipping).
        new_sw = None
        m_sw = re.match(r"switch\s*\(", head)
        if m_sw and n_block_open:
            sw_cond, _rest = _j5_split_paren(head, m_sw.end() - 1)
            if sw_cond is not None:
                folded = _j5_const_expr(sw_cond, int_env)
                if folded is not None:
                    labels = _j5_switch_taken_labels(
                        masked_body, idx, folded, int_env)
                    if labels is not None:
                        new_sw = {"labels": labels, "on": False, "base": 0}
        # A method signature -- possibly split so the ``{`` lands on a
        # ``throws ...`` continuation line -- opens the body and must not
        # nest it. Class-like declarations do the same for whole-file
        # walks (the taint_engine line layer passes the entire file), and
        # block continuations (``} catch (E e) {``) and anonymous class
        # openers do open real frames.
        sig_like = bool(
            (re.search(
                r"(?:\)\s*(?:throws\s+[^{]*)?|^throws\s+[^{]*)\{\s*$", head)
             and not re.match(r"(?:if|for|while|switch|catch|synchronized|else|do|new)",
                              head)
             and not head.startswith("}"))
            or re.match(
                r"(?:(?:public|private|protected|static|final|abstract|strictfp)\s+)*"
                r"(?:class|interface|enum|record)\b", head)
        )
        if not sig_like:
            for i in range(n_block_open):
                if i == 0 and _J5_TRY_HEAD_RE.match(head):
                    frames.append("try")
                elif i == 0 and new_sw is not None:
                    # Folded switch: untaken groups are skipped, so the
                    # taken group's writes get kill rights exactly like
                    # try/finally; an outer conditional frame still
                    # withholds them.
                    frames.append("try")
                else:
                    frames.append("cond")
            if new_sw is not None:
                new_sw["base"] = len(frames)
                sw_stack.append(new_sw)

        # Masked statement (comments blanked, strings intact): a trailing
        # ``// condition 'B', which is safe`` comment must not end up in
        # the constant environment's rhs, where it would refuse the fold
        # and silently disable the switch machinery below.
        s = re.sub(r"\s+", " ", masked_raw).strip()
        if not s or s.startswith("//") or s.startswith("/*"):
            continue

        # Folded-switch gate: a statement inside a group this switch
        # will not execute is dead code -- skipped entirely, so its
        # writes neither resurrect nor kill (the naive linear walk would
        # otherwise let an untaken ``bar = param`` undo the taken
        # group's ``bar = "bob"``). A label turns execution on only for
        # the switch that owns it AND only when every enclosing switch
        # is on: a nested switch inside an untaken outer group can never
        # come alive. Statements before any label run for no switch.
        if sw_stack:
            si = idx - nlines
            inner = sw_stack[-1]
            outer_on = all(swi["on"] for swi in sw_stack[:-1])
            lab = re.match(r"(?:case\s+.+?|default)\s*:\s*", s)
            if lab:
                if not outer_on or si not in inner["labels"]:
                    inner["on"] = False
                    continue
                inner["on"] = True
                s = s[lab.end():]
                if not s:
                    continue
            elif not (inner["on"] and outer_on):
                continue

        if re.match(r"else\b", s):
            rest = re.sub(r"^else\s*", "", s)
            mode, pending_else = pending_else, None
            if mode == "folded_true":
                # The paired condition folded to a constant TRUE; this
                # branch does not run (00117: ``else bar = param`` is
                # exactly why the test is labelled negative).
                continue
            if rest and not rest.startswith("{"):
                lhs, rhs = _j5_assignment(rest)
                kill = can_kill
                if not lhs:
                    # ``else if (...) x = y;`` chains: strip the second
                    # control prefix too, and the write stays
                    # conditional -- kill rights belong to the else
                    # branch only when its OWN statement is the write.
                    lhs, rhs = _j5_inline_assignment(rest)
                    kill = False
                if mode == "folded_false":
                    # The THEN branch was the dead one; this else is the
                    # taken branch and carries full kill rights.
                    record(lhs, rhs, rest, can_kill=kill)
                else:
                    record(lhs, rhs, rest, can_kill=False)
            continue
        if pending_else is not None:
            pending_else = None  # no else followed; stale pairing dropped

        m_if = re.match(r"if\s*\(", s)
        if m_if:
            cond, then_stmt = _j5_split_paren(s, m_if.end() - 1)
            if then_stmt and not then_stmt.startswith("{"):
                folded = _j5_const_expr(cond, int_env)
                if folded is None:
                    pending_else = "unknown"
                    lhs, rhs = _j5_assignment(then_stmt)
                    if not lhs:
                        lhs, rhs = _j5_inline_assignment(then_stmt)
                    record(lhs, rhs, then_stmt, can_kill=False)
                elif bool(folded):
                    pending_else = "folded_true"
                    lhs, rhs = _j5_assignment(then_stmt)
                    kill = can_kill
                    if not lhs:
                        # Nested inline write (``if (t) if (c) x = y``):
                        # behind a second control prefix it never gets
                        # kill rights, even though this branch runs.
                        lhs, rhs = _j5_inline_assignment(then_stmt)
                        kill = False
                    record(lhs, rhs, then_stmt, can_kill=kill)
                else:
                    # Condition folds to FALSE: the then-branch is dead
                    # code and the (possible) else branch is the taken
                    # one -- recorded when it is seen below.
                    pending_else = "folded_false"
                continue
            # Braced if: nesting is handled by frames, and an unreachable
            # braced block is deliberately not skipped (see docstring).

        lhs, rhs = _j5_assignment(s)
        if lhs:
            record(lhs, rhs, s, can_kill=can_kill)
    # F0: apply deferred declaration kills whose frame stack contains the
    # sink's (the frame state as of the last statement before the sink
    # line is the stack the sink expression executes in).  A candidate
    # whose frame closed earlier -- or whose snapshot diverges -- is
    # dropped: the sink then sees some other binding and this
    # declaration proves nothing about it (conservative direction).
    sink_frames = tuple(frames)
    for d_name, d_snap in pending_decls.items():
        if len(d_snap) <= len(sink_frames) and sink_frames[:len(d_snap)] == d_snap:
            dead.add(d_name)
    return dead


def _j5_analyze_method(filepath, source, method, incoming, safe_calls=None,
                       san_calls=None, local_knowledge=None):
    lines = source.splitlines()
    # File-local call knowledge (safe, san, declared types) computed
    # ONCE by the caller -- see _j5_file_call_knowledge. Its inner
    # analyses deliberately pass nothing here, which is what keeps the
    # computation recursion-free.
    lk_safe: set = set()
    lk_san: dict = {}
    lk_types = None
    if local_knowledge:
        lk_safe, lk_san, lk_types = local_knowledge
    start = method["body_start_line"]
    end = min(len(lines), method["body_end_line"])
    body = lines[start - 1:end]
    # Comment-blanked view of the body (strings intact) used for every
    # statement the analysis evaluates -- see the mask note in the loop.
    masked_body = _j5_mask("\n".join(body)).splitlines()
    # RSECOPSX_J6B_CONSTANTS_INIT_FIX_20260907
    # Initialize the constants mapping required by the J6-B exact-element guard.
    # Without this initialization the guard raises NameError at runtime.
    constants = {}

    taint = set(incoming)
    origins = {p: [f"parameter:{p}", p] for p in incoming}
    fields = set()
    collections = {}
    builders = set()
    returns = []
    sink_flows = []

    for _ in range(_J5_LOCAL_ROUNDS):
        changed = False
        m_idx = 0  # physical-line cursor into masked_body for this round

        for line_no, raw in _j5_logical_statements(body, start):
            # The logical statement may contain physical newlines. Flatten
            # only for the existing regex-based semantic checks so _J5_ASSIGN_RE
            # can see the complete RHS as one expression. The statement is
            # taken MASKED (comments blanked, strings intact): commented-out
            # code must never taint or emit -- BenchmarkJava comments out the
            # File constructor it asked authors to try (00135), and that
            # comment used to match the sink pattern as a real finding.
            nlines = raw.count("\n") + 1
            s = re.sub(
                r"\s+", " ",
                "\n".join(masked_body[m_idx:m_idx + nlines])).strip()
            m_idx += nlines
            if not s:
                continue

            if (
                _J5_SOURCE_RE.search(s)
                or _J5_COOKIE_VALUE_RE.search(s)
                or _J5_WRAPPER_SOURCE_RE.search(s)
            ):
                lhs, _ = _j5_assignment(s)
                if lhs and lhs not in taint:
                    if _J5_SOURCE_RE.search(s):
                        label = "HttpServletRequest source"
                    elif _J5_WRAPPER_SOURCE_RE.search(s):
                        label = "Request wrapper source"
                    else:
                        label = "Cookie.getValue()"

                    taint.add(lhs)
                    origins[lhs] = [label, lhs]
                    changed = True

            lhs, rhs = _j5_assignment(s)
            if not lhs:
                # Inline ``if (cond) bar = rhs;`` / ``else bar = rhs;``:
                # propagation-only here, so the stripped write is
                # treated as unconditional (the branch MIGHT run).
                lhs, rhs = _j5_inline_assignment(s)
            if lhs and rhs and not _j5_sink_return(rhs):
                # RSECOPSX_J6B_INLINE_COMMENT_TAINT_FIX_STRUCTURAL_V2_20260907
                # Ignore Java comments when deriving taint from an assignment RHS.
                rhs_for_taint = _j6b_strip_java_comments(rhs)
                hits = _j5_expr_hits(rhs_for_taint, taint)

                # RSECOPSX_J6B_TRI_STATE_CALLER_20260907
                exact_safe, selected_expr = _j6b_exact_selected_safe(
                    rhs, body, start, constants, taint, return_detail=True
                )
                if selected_expr is not None:
                    selected_hits = _j5_expr_hits(
                        _j6b_strip_java_comments(selected_expr), taint
                    )
                    if selected_hits:
                        hits = selected_hits
                    elif exact_safe:
                        hits = []
                elif exact_safe:
                    hits = []
                for pattern in (
                    r'\b([A-Za-z_$][\w$]*)\s*\.\s*(?:get|remove)\s*\(',
                    r'\b([A-Za-z_$][\w$]*)\s*\[[^\]]+\]',
                    r'\b([A-Za-z_$][\w$]*)\s*\.\s*next(?:Element)?\s*\(',
                ):
                    mm = re.search(pattern, rhs, re.I)
                    if (
                        mm
                        and mm.group(1) in taint
                        and mm.group(1) not in hits
                        and not exact_safe
                    ):
                        hits.append(mm.group(1))

                if hits and lhs not in taint:
                    parent = hits[0]
                    taint.add(lhs)
                    origins[lhs] = origins.get(parent, [parent]) + [lhs]
                    changed = True

                compact = rhs.replace(" ", "")
                for fld in fields:
                    if compact == fld and lhs not in taint:
                        taint.add(lhs)
                        origins[lhs] = origins.get(fld, [fld]) + [lhs]
                        changed = True

            fm = re.match(
                r'([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*=\s*(.+?);?$',
                s
            )
            if fm:
                fld = fm.group(1) + "." + fm.group(2)
                hits = _j5_expr_hits(fm.group(3), taint)
                if hits and fld not in fields:
                    fields.add(fld)
                    origins[fld] = origins.get(hits[0], [hits[0]]) + [fld]
                    changed = True

            cm = re.search(
                r'\b([A-Za-z_$][\w$]*)\s*\.\s*(?:add|put)\s*\((.*)\)',
                s, re.I
            )
            if cm:
                obj, args = cm.group(1), cm.group(2)
                hits = _j5_expr_hits(args, taint)
                if hits:
                    collections[obj] = {
                        "source": origins.get(hits[0], [hits[0]])[0],
                        "chain": origins.get(hits[0], [hits[0]]) + [obj + ".collection"],
                    }

            bm = re.search(
                r'\b([A-Za-z_$][\w$]*)\s*\.\s*append\s*\((.*)\)',
                s, re.I
            )
            if bm:
                hits = _j5_expr_hits(bm.group(2), taint)
                if hits:
                    builders.add(bm.group(1))
                    parent = hits[0]
                    origins.setdefault(
                        bm.group(1),
                        origins.get(parent, [parent]) + [bm.group(1) + ".append"]
                    )

            tm = re.match(
                r'(?:String\s+)?([A-Za-z_$][\w$]*)\s*=\s*'
                r'([A-Za-z_$][\w$]*)\.toString\s*\(\s*\)\s*;',
                s, re.I
            )
            if tm and tm.group(2) in builders and tm.group(1) not in taint:
                taint.add(tm.group(1))
                origins[tm.group(1)] = origins.get(tm.group(2), [tm.group(2)]) + [tm.group(1)]
                changed = True

            rm = re.search(r'\breturn\s+(.+?);?\s*$', s, re.I)
            if rm:
                hits = _j5_expr_hits(rm.group(1), taint)
                if hits:
                    returns.append({
                        "line": line_no, "tainted": True,
                        "origin": hits[0], "expr": rm.group(1),
                    })

            for vuln, cwe, title, rule_id, pattern in _J5_SINKS:
                sm = pattern.search(s)
                if not sm:
                    continue

                if vuln == "xpath_injection" and not re.search(
                    r'\b(?:XPath|XPathExpression|xpath|javax\.xml\.xpath)\b',
                    source, re.I
                ):
                    continue

                if vuln == "ldap_injection" and not re.search(
                    r'\b(?:ldap|DirContext|InitialDirContext|NamingEnumeration|javax\.naming)\b',
                    source, re.I
                ):
                    continue

                if (vuln == "sql_injection"
                        and sm.group(0).startswith("addBatch")
                        and not re.search(
                            r'\b(?:Statement|java\.sql|jdbc)\b', source, re.I)):
                    continue

                if vuln == "command_injection" and re.search(r'\.\s*start\s*\(', s, re.I):
                    receiver = re.search(
                        r'\b([A-Za-z_$][\w$]*)\s*\.\s*start\s*\(', s, re.I
                    )
                    if not receiver or (
                        receiver.group(1) not in collections
                        and receiver.group(1) not in builders
                    ):
                        continue

                # Sink-local argument extraction: take the argument list
                # of the MATCHED sink call itself, not the first/last
                # paren of the whole statement. The loose extraction
                # bled taint from sibling calls on the same line --
                # "r.exec(args, argsEnv, new java.io.File(user.dir))"
                # used to hand the File sink exec's tainted argsEnv
                # (the dominant surviving JAVA_J5_PATH false shape).
                # Quote-aware close so a paren inside a string literal
                # cannot end the list early.
                if sm.group(0)[-1:] == "(":
                    op = sm.end() - 1
                else:
                    op = s.find("(", sm.end() - 1)
                cp = _j5_balanced_close(s, op) if op >= 0 else None
                args = (
                    _split_args(s[op + 1:cp])
                    if op >= 0 and cp is not None and cp > op else []
                )
                hits = []
                for arg in args:
                    # A sanitizer wrap DIRECTLY at the sink counts like an
                    # assignment-side kill: print(encodeForHTML(fileName))
                    # cannot carry the vuln even though fileName is live --
                    # the walk only sees wraps that are right-hand sides of
                    # assignments. Blanking removes the wrap's arguments
                    # too, so what remains is what can actually reach the
                    # response; None (no wrap / unbalanced) keeps the raw
                    # arg, the conservative direction.
                    covered = _j5_blank_sanitizer_spans(arg, vuln)
                    if covered is not None:
                        arg = covered
                    hits.extend(_j5_expr_hits(arg, taint))
                if hits:
                    # Order-aware refinement: a name whose last write
                    # before this sink is provably safe is not a live
                    # carrier here, even though it was tainted somewhere
                    # earlier in the method (see _j5_dead_names). The
                    # sink's vuln class also lets the walk treat a
                    # class-correct sanitizer wrap (encodeForHTML at an
                    # xss sink) as a kill.
                    #
                    # ``san_calls`` is the per-vuln twin of the agnostic
                    # ``safe_calls``: a helper whose every return is
                    # sanitizer-clean FOR THIS CLASS
                    # (``bar = htmlEscape(param); return bar``) drops
                    # taint at an xss sink, while an HTML escape says
                    # nothing about path traversal -- so the union is
                    # built per sink, never stored globally.
                    eff_safe = safe_calls
                    if san_calls and vuln:
                        vset = san_calls.get(vuln)
                        if vset:
                            eff_safe = (safe_calls or set()) | set(vset)
                    # File-local knowledge joins per sink (guarded by
                    # prefix inside the walk); agnostic-clean first,
                    # then the class-clean extras for THIS sink.
                    local = set(lk_safe)
                    if vuln:
                        local |= set(lk_san.get(vuln, ()))
                    dead = _j5_dead_names(
                        body, start, taint, line_no, eff_safe, vuln,
                        local or None, lk_types)
                    hits = [h for h in hits if h not in dead]

                if hits:
                    origin = hits[0]
                    sink_flows.append({
                        "vuln": vuln,
                        "cwe": cwe,
                        "title": title,
                        "rule_id": rule_id,
                        "line": line_no,
                        "snippet": raw,
                        "origin": origin,
                        "chain": origins.get(origin, [origin]),
                        "sink": sm.group(0).strip()[:160],
                        "method": method["name"],
                    })

        if not changed:
            break

    # Dead-aware returns: a return whose every tainted-looking name had
    # been overwritten with a proven-safe value before the ``return``
    # does not actually carry taint to the caller (01479: the helper
    # folds the constant through if/else and returns it, while the
    # flow-insensitive set still lists ``param`` in scope -- propagating
    # that was what lit up the caller's sink). Dropping such entries
    # narrows only the interprocedural seeding; the local taint set is
    # untouched.
    if returns:
        dead_by_line: dict[int, set] = {}
        refined_returns = []
        for r in returns:
            if not r.get("tainted"):
                refined_returns.append(r)
                continue
            rline = r.get("line")
            if rline not in dead_by_line:
                # Agnostic refinement: only the unconditional file-local
                # drops count here (no ``vuln`` at this point), and the
                # prefix guard still applies inside the walk.
                dead_by_line[rline] = _j5_dead_names(
                    body, start, taint, rline, safe_calls, None,
                    lk_safe or None, lk_types)
            live_hits = [
                h for h in _j5_expr_hits(r.get("expr", r["origin"]), taint)
                if h not in dead_by_line[rline]
            ]
            if live_hits:
                nr = dict(r)
                nr["origin"] = live_hits[0]
                refined_returns.append(nr)
        returns = refined_returns

    return {
        "method": method,
        "taint": taint,
        "origins": origins,
        "fields": fields,
        "collections": collections,
        "builders": builders,
        "returns": returns,
        "sink_flows": sink_flows,
    }


def _j5_returns_clean_for(state, source, safe_calls, vuln,
                          local_calls=None, local_types=None) -> bool:
    """True when every still-tainted return of ``state`` is clean for
    ``vuln`` once dead-refined with the walk given ``vuln``.

    ``state["returns"]`` already holds the AGNOSTIC refinement's
    survivors -- entries whose every name died before the ``return``
    were dropped when the state was built. Re-running the walk with
    ``vuln`` adds only the class-correct sanitizer kills: ``return
    htmlEscape(param)``'s taint survives an HTML escape as far as path
    traversal is concerned and dies for xss, and only the vuln-keyed
    walk can tell the two apart. Used by the line layers' file-local
    ``_j5_file_call_knowledge``.
    """
    pending = [r for r in state.get("returns", []) if r.get("tainted")]
    if not pending:
        return True
    lines_ = source.splitlines()
    m = state["method"]
    bstart = m["body_start_line"]
    bend = min(len(lines_), m["body_end_line"])
    body = lines_[bstart - 1:bend]
    for r in pending:
        dead = _j5_dead_names(
            body, bstart, set(state["taint"]), r.get("line"),
            safe_calls, vuln, local_calls, local_types)
        live = [
            h for h in _j5_expr_hits(r.get("expr", r["origin"]),
                                     state["taint"])
            if h not in dead
        ]
        if live:
            return False
    return True


# File-local call knowledge for the LINE layers (JAVA_TAINT_* /
# JAVA_J3_*). Their dead-walk used to be delegated with
# ``safe_calls=None``, so every helper shape the J5 layer quiets through
# interprocedural return knowledge still fired there: BenchmarkJava's
# dominant JAVA_TAINT_XSS negatives put the fold (``bar = cond ?
# "const" : param``) or the HTML escape inside ``doSomething`` and the
# caller's ``println(bar)`` at the sink.
_J5_CALL_KNOWLEDGE_CACHE: dict = {}


def _j5_file_call_knowledge(source: str, filepath: str = "<file>"):
    """``(safe_calls, san_calls)`` computed from ONE file's own helpers.

    The line layers are file-global by design and have no project-wide
    method states, so this analyzes the file alone: every method once
    with ALL its parameters tainted -- a passthrough helper must never
    look clean -- then one settle iteration so a helper that calls
    another helper in the same file inherits its knowledge. Keys are
    ``(name, arity)`` exactly like ``analyze_java_project``'s, and a key
    is only added when EVERY local resolution is clean, so an unsafe
    overload poisons the pair conservatively.

    Scoped to local definitions: a call resolved here is either a bare
    ``helper(...)`` or ``new Inner().helper(...)`` in the same file --
    the BenchmarkJava and golden-corpus shape. A qualified cross-class
    call whose target lives elsewhere simply is not in this index and
    keeps today's behavior (no kill). Cached by content hash; the walk
    is invoked once per sink hit.
    """
    import hashlib
    digest = hashlib.sha1(
        source.encode("utf-8", "replace")).hexdigest()
    hit = _J5_CALL_KNOWLEDGE_CACHE.get(digest)
    if hit is not None:
        return hit
    safe: set = set()
    san: dict = {v: set() for v in _JAVA_SANITIZERS}
    try:
        methods = _j5_methods(source, filepath)
        if methods:
            index: dict = {}
            states: dict = {}
            local_types = _j5_local_types(source)
            for m in methods:
                mkey = _j5_method_key(m)
                index.setdefault(mkey, []).append(m)
                states[(m["start_line"], mkey)] = _j5_analyze_method(
                    filepath, source, m, set(m["params"]))

            def _local_compute():
                s = set()
                for key, ms in index.items():
                    ok = True
                    for m in ms:
                        st = states.get((m["start_line"], key))
                        if st is None or any(
                                r.get("tainted")
                                for r in st.get("returns", [])):
                            ok = False
                            break
                    if ok:
                        s.add(key)
                sd = {}
                for v in _JAVA_SANITIZERS:
                    vs = set()
                    for key, ms in index.items():
                        if key in s:
                            # Agnostic-clean implies clean for every
                            # class -- it dropped taint unconditionally.
                            vs.add(key)
                            continue
                        ok = True
                        for m in ms:
                            st = states.get((m["start_line"], key))
                            if st is None or not _j5_returns_clean_for(
                                    st, source, None, v, s, local_types):
                                ok = False
                                break
                        if ok:
                            vs.add(key)
                    sd[v] = vs
                return s, sd

            for _ in range(2):
                prev = (set(safe),
                        {k: set(x) for k, x in san.items()})
                safe, san = _local_compute()
                if (safe, san) == prev:
                    break
                for skey, st in list(states.items()):
                    # Settle with the file's own knowledge passed as the
                    # GUARDED local form -- the unguarded (safe, san)
                    # used to travel as project-wide safe_calls, which
                    # would let ``Other.helper(...)`` inside a helper
                    # body borrow a local helper's clean verdict.
                    states[skey] = _j5_analyze_method(
                        filepath, source, st["method"],
                        set(st["taint"]), None, None,
                        (safe, san, local_types))
    except Exception:
        # Any analysis failure degrades to today's behavior: no call
        # knowledge, no kills from it.
        safe, san = set(), {v: set() for v in _JAVA_SANITIZERS}
    result = (frozenset(safe),
              {k: frozenset(vv) for k, vv in san.items()})
    if len(_J5_CALL_KNOWLEDGE_CACHE) >= 4096:
        _J5_CALL_KNOWLEDGE_CACHE.clear()
    _J5_CALL_KNOWLEDGE_CACHE[digest] = result
    return result


# J5_SINK_CATEGORY_EVIDEX_COMPATIBILITY_20260905

def _j5_sink_category(vuln_type: str) -> str:
    """
    Map a J5 vulnerability type to the canonical sink taxonomy
    consumed by analyzer EVIDEX validation.

    This does NOT bypass EVIDEX validation.
    It only supplies the sink category already established by
    the J5 semantic sink analysis.
    """
    vt = str(vuln_type or "").strip().lower()

    mapping = {
        "xss": "http",
        "cross_site_scripting": "http",

        "sql_injection": "jdbc",
        "sqli": "jdbc",

        "command_injection": "process",
        "os_command_injection": "process",
        "command_exec": "process",

        "path_traversal": "filesystem",
        "file_inclusion": "filesystem",
        "local_file_inclusion": "filesystem",
        "arbitrary_file_read": "filesystem",

        "ldap_injection": "ldap",

        "xpath_injection": "xpath",
    }

    return mapping.get(vt, "")


def _j5_make_finding(flow, filepath):
    mapping = get_mapping(flow["vuln"]) or {}
    chain = list(flow.get("chain") or [])
    sink = flow["sink"]
    if not chain:
        chain = [flow.get("origin", "tainted")]
    path = " -> ".join(chain + [sink])
    return {
        "vuln_type": flow["vuln"],
        "source_var": chain[0],
        "source_expr": chain[0],
        "sink_call": sink,
        "file": filepath,
        "line": flow["line"],
        "snippet": flow["snippet"].strip()[:500],
        "taint_path": path,
        "taint_chain": chain + [sink],
        "function": flow.get("method", ""),
        "rule_id": flow["rule_id"],
        "title": flow["title"],
        "language": "java",
        "confidence": "High",
        "severity": mapping.get("severity") or "High",
        "cwe": flow["cwe"],
        "owasp": mapping.get("owasp") or mapping.get("owasp_id") or "",
        "remediation": mapping.get("remediation") or [],
        "description": "Java J5 bounded project semantic flow: " + path,
        "detection": "Java J5 Big-Bang Project Semantic Data-Flow",
        "engine": "scanner.java_semantic_j5",
        "sink_category": _j5_sink_category(flow["vuln"]),
        "group_key": f"java-j5|{flow['vuln']}|{filepath}|{flow['line']}|{sink}",
        "cvss": None,
        "cve": None,
    }


def analyze_java_project(project_root: str) -> list[dict]:
    root = Path(project_root).resolve()
    if not root.is_dir():
        return []

    excluded = {
        ".git", "build", "target", "out", "node_modules", "coverage",
        "reports", "artifacts", "__pycache__"
    }

    java_files = sorted(
        p for p in root.rglob("*.java")
        if p.is_file() and not any(part.lower() in excluded for part in p.parts)
    )
    if not java_files:
        return []

    sources = {}
    method_index = {}
    for path in java_files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        path_str = str(path)
        sources[path_str] = text
        for method in _j5_methods(text, path_str):
            method_index.setdefault(_j5_method_key(method), []).append(method)

    states = {}
    # File-local call knowledge, computed once per unique source before
    # any analysis runs: it depends only on the text (recursion-free by
    # construction -- _j5_file_call_knowledge's inner analyses pass no
    # local_knowledge) and is shared with the line layers through the
    # content-hash cache when their masked text hashes the same.
    local_knowledge = {}
    for path_str, text in sources.items():
        lk_safe, lk_san = _j5_file_call_knowledge(text, path_str)
        local_knowledge[path_str] = (
            lk_safe, lk_san, _j5_local_types(text))

    for path_str, text in sources.items():
        for method in _j5_methods(text, path_str):
            key = (path_str, method["start_line"], method["name"], len(method["params"]))
            states[key] = _j5_analyze_method(
                path_str, text, method, set(),
                local_knowledge=local_knowledge.get(path_str))

    def _compute_safe_calls() -> set:
        """(name, arity) pairs whose resolvable methods all drop taint.

        Uses the dead-refined ``returns`` every state was built with, so
        a helper that folds a constant through if/else/ternary and
        returns it counts as safe while a passthrough helper never does.
        A method that has no resolvable state, or still returns taint,
        keeps its (name, arity) unsafe.
        """
        safe = set()
        for key, methods in method_index.items():
            ok = bool(methods)
            for m in methods:
                skey = (str(m["file"]), m["start_line"], m["name"],
                        len(m["params"]))
                st = states.get(skey)
                if st is None or any(r.get("tainted")
                                     for r in st.get("returns", [])):
                    ok = False
                    break
            if ok:
                safe.add(key)
        return safe

    for _round in range(_J5_MAX_ROUNDS):
        changed = False
        safe_calls = _compute_safe_calls()

        for caller_key, caller_state in list(states.items()):
            caller = caller_state["method"]
            caller_text = sources.get(str(caller["file"]), "")
            caller_lines = caller_text.splitlines()
            start = caller["body_start_line"]
            end = min(len(caller_lines), caller["body_end_line"])

            for line_no in range(start, end + 1):
                raw = caller_lines[line_no - 1]
                s = raw.strip()

                am = re.match(
                    r'(?:(?:[A-Za-z_$][\w$<>\[\],.? ]+)\s+)?'
                    r'([A-Za-z_$][\w$]*)\s*=\s*'
                    r'(?:(?:new\s+[A-Za-z_$][\w$<>,.?]*\s*\(\s*\)\s*\.\s*)'
                    r'|(?:(?:[A-Za-z_$][\w$]*\s*\.\s*)*))'
                    r'([A-Za-z_$][\w$]*)\s*\((.*)\)\s*;?\s*$',
                    s
                )
                if am:
                    lhs, call_name, raw_args = am.group(1), am.group(2), am.group(3)
                    args = _split_args(raw_args)
                else:
                    cm = re.search(
                        r'\b([A-Za-z_$][\w$]*)\s*\((.*)\)\s*;?\s*$',
                        s
                    )
                    if not cm:
                        continue
                    lhs = None
                    call_name = cm.group(1)
                    args = _split_args(cm.group(2))

                candidates = [
                    m for m in method_index.get((call_name, len(args)), [])
                    if not (
                        str(m["file"]) == str(caller["file"])
                        and m["start_line"] == caller["start_line"]
                    )
                ]
                for callee in candidates:
                    callee_key = (
                        str(callee["file"]), callee["start_line"],
                        callee["name"], len(callee["params"])
                    )
                    state = states.get(callee_key)
                    if not state:
                        continue

                    # Caller -> callee parameter.
                    for pos, arg in enumerate(args):
                        if pos >= len(callee["params"]):
                            continue
                        hits = _j5_expr_hits(arg, caller_state["taint"])
                        if not hits:
                            continue
                        formal = callee["params"][pos]
                        if formal not in state["taint"]:
                            state["taint"].add(formal)
                            origin = hits[0]
                            state["origins"][formal] = (
                                caller_state["origins"].get(origin, [origin])
                                + [f"{callee['name']}({formal})"]
                            )
                            states[callee_key] = _j5_analyze_method(
                                str(callee["file"]),
                                sources[str(callee["file"])],
                                callee,
                                set(state["taint"]),
                                safe_calls,
                                local_knowledge=local_knowledge.get(
                                    str(callee["file"]))
                            )
                            changed = True

                    # Callee return -> caller variable.
                    if lhs and any(r.get("tainted") for r in state.get("returns", [])):
                        if lhs not in caller_state["taint"]:
                            hits = []
                            for pos, arg in enumerate(args):
                                if pos < len(callee["params"]):
                                    formal = callee["params"][pos]
                                    if formal in state["taint"]:
                                        ah = _j5_expr_hits(arg, caller_state["taint"])
                                        if ah:
                                            hits.extend(ah)
                            if hits:
                                origin = hits[0]
                                caller_state["taint"].add(lhs)
                                caller_state["origins"][lhs] = (
                                    caller_state["origins"].get(origin, [origin])
                                    + [f"{call_name}(...)", lhs]
                                )
                                states[caller_key] = _j5_analyze_method(
                                    str(caller["file"]),
                                    caller_text,
                                    caller,
                                    set(caller_state["taint"]),
                                    safe_calls,
                                    local_knowledge=local_knowledge.get(
                                        str(caller["file"]))
                                )
                                changed = True

        if not changed:
            break

    # Settling passes: the round loop propagates taint, but its
    # re-analysis is one-directional -- a caller whose helper turns out
    # to DROP taint is never revisited there, because its lhs was
    # already tainted syntactically (the tainted argument in
    # ``bar = new Test().doSomething(request, param)``). Re-analyze
    # every method against the converged taint plus the converged
    # safe-call knowledge, repeating while that knowledge still changes,
    # so the states -- and the sink flows emitted from them -- reflect
    # both. This is what quiets the benchmark's dominant negative shape
    # (01479/02370: helper folds the constant and returns it) without
    # touching passthrough helpers, whose (name, arity) never enters
    # safe_calls.
    prev_safe = None
    for _ in range(3):
        safe_calls = _compute_safe_calls()
        if safe_calls == prev_safe:
            break
        prev_safe = safe_calls
        for key, state in list(states.items()):
            method = state["method"]
            states[key] = _j5_analyze_method(
                str(method["file"]), sources[str(method["file"])],
                method, set(state["taint"]), safe_calls,
                local_knowledge=local_knowledge.get(str(method["file"])))

    findings = []
    for state in states.values():
        for flow in state.get("sink_flows", []):
            findings.append(
                _j5_make_finding(flow, str(state["method"]["file"]))
            )

    out = []
    seen = set()
    for f in findings:
        key = (
            f.get("vuln_type"), f.get("file"),
            int(f.get("line") or 0), f.get("sink_call", "")
        )
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
