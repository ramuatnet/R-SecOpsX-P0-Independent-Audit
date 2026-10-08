import re

try:
    from scanner import java_semantic_j5 as _j5
except Exception:
    from . import java_semantic_j5 as _j5

def _switch_info(source):
    lines = source.splitlines(True)
    sw = None
    for i, line in enumerate(lines):
        if re.search(r"\bswitch\s*\(", line):
            sw = i
            break
    if sw is None:
        return None
    pre = "\n".join(x.rstrip("\n") for x in lines[max(0, sw-30):sw])
    sm = re.search(r'String\s+\w+\s*=\s*"([^"]+)"', pre)
    cm = re.search(r"char\s+\w+\s*=\s*\w+\.charAt\(\s*(\d+)\s*\)", pre)
    target = None
    if sm and cm:
        idx = int(cm.group(1))
        if 0 <= idx < len(sm.group(1)):
            target = sm.group(1)[idx]
    depth = 0
    end = None
    for j in range(sw, len(lines)):
        depth += lines[j].count("{") - lines[j].count("}")
        if j > sw and depth <= 0:
            end = j
            break
    if end is None:
        return None
    labels = []
    for i in range(sw, end + 1):
        m = re.match(r"^\s*case\s+(.+?)\s*:", lines[i])
        d = re.match(r"^\s*default\s*:", lines[i])
        if m:
            v = m.group(1).strip().strip("()")
            if len(v) >= 2 and v[0] == v[-1] and v[0] in chr(39)+chr(34):
                v = v[1:-1]
            labels.append((i, v))
        elif d:
            labels.append((i, "default"))
    return {"switch_line": sw + 1, "end_line": end + 1, "target": target, "labels": labels}

def _branch_scoped_source(source):
    info = _switch_info(source)
    if info is None:
        return source, False, "NO_SWITCH"
    if info["target"] is None:
        return source, False, "UNKNOWN_TARGET"
    labels = info["labels"]
    matches = [k for k, item in enumerate(labels) if item[1] == info["target"]]
    if len(matches) != 1:
        return source, False, "MULTI_FEASIBLE_OR_UNRESOLVED"
    selected = matches[0]
    lines = source.splitlines(True)
    removed = []
    for k, (line_no, label) in enumerate(labels):
        if k == selected:
            continue
        stop = labels[k+1][0] if k + 1 < len(labels) else info["end_line"] - 1
        for x in range(line_no + 1, stop):
            if lines[x].strip():
                removed.append(x + 1)
                lines[x] = "\n" if lines[x].endswith("\n") else ""
    return "".join(lines), True, "DETERMINISTIC_SINGLE_BRANCH"

def analyze_method(path, source, method, incoming=None):
    incoming = set(incoming or set())
    masked, activated, reason = _branch_scoped_source(source)
    state = _j5._j5_analyze_method(path, masked if activated else source, method, incoming)
    state["_switch_vnext_adapter_activated"] = activated
    state["_switch_vnext_activation_reason"] = reason
    return state