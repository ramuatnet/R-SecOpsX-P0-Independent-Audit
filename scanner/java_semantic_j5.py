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


def _expr_tainted(expr: str, tainted: set[str], fields: set[str], builders: set[str]) -> set[str]:
    e=expr or ""
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

_J5_METHOD_RE = re.compile(
    r'(?m)^[ \t]*(?:(?:public|protected|private|static|final|synchronized|abstract|native|strictfp)\s+)*'
    r'(?:<[\w\s,? extends super.&]+>\s+)?'
    r'(?:[A-Za-z_$][\w$<>\[\],.? ]*\s+)?'
    r'([A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*(?:throws\s+[^{]+)?\{'
)

_J5_CONTROL_WORDS = {"if", "for", "while", "switch", "catch", "synchronized", "try", "do"}

_J5_SOURCE_RE = re.compile(
    r'\b(?:request|req)\s*\.\s*'
    r'(?:getParameter|getParameterMap|getParameterNames|getParameterValues|getHeader|getHeaders|getCookies|getCookie|'
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
     re.compile(r'\b(?:[A-Za-z_$][\w$]*\.)?'
                r'(?:prepareCall|prepareStatement|executeQuery|executeUpdate|execute)\s*\(', re.I)),
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
    r'\b(?:executeQuery|executeUpdate|execute|prepareCall|prepareStatement|'
    r'search|compile|evaluate|start|exec)\s*\(', re.I
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


def _j5_expr_hits(expr, taint):
    hits = []
    for name in taint:
        if re.search(r'(?<![\w$])' + re.escape(name) + r'(?![\w$])',
                     expr or ""):
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
    rhs_text = _j6b_strip_java_comments(rhs or "").strip().rstrip(";").strip()
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


def _j5_analyze_method(filepath, source, method, incoming):
    lines = source.splitlines()
    start = method["body_start_line"]
    end = min(len(lines), method["body_end_line"])
    body = lines[start - 1:end]
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

        for line_no, raw in _j5_logical_statements(body, start):
            # The logical statement may contain physical newlines. Flatten
            # only for the existing regex-based semantic checks so _J5_ASSIGN_RE
            # can see the complete RHS as one expression.
            s = re.sub(r"\s+", " ", raw).strip()
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
                    returns.append({"line": line_no, "tainted": True, "origin": hits[0]})

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

                if vuln == "command_injection" and re.search(r'\.\s*start\s*\(', s, re.I):
                    receiver = re.search(
                        r'\b([A-Za-z_$][\w$]*)\s*\.\s*start\s*\(', s, re.I
                    )
                    if not receiver or (
                        receiver.group(1) not in collections
                        and receiver.group(1) not in builders
                    ):
                        continue

                op = s.find("(")
                cp = s.rfind(")")
                args = _split_args(s[op + 1:cp]) if op >= 0 and cp > op else []
                hits = []
                for arg in args:
                    hits.extend(_j5_expr_hits(arg, taint))

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
    for path_str, text in sources.items():
        for method in _j5_methods(text, path_str):
            key = (path_str, method["start_line"], method["name"], len(method["params"]))
            states[key] = _j5_analyze_method(path_str, text, method, set())

    for _round in range(_J5_MAX_ROUNDS):
        changed = False

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
                                set(state["taint"])
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
                                    set(caller_state["taint"])
                                )
                                changed = True

        if not changed:
            break

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
