"""Independent npm lockfile edge oracle — Task 6 Phase D (validation artifact).

Re-implements package-lock.json v2/v3 parent->child resolution from first
principles WITHOUT importing analysis/npm_lock_graph_v2, then compares the
result against (a) the engine edges and (b) the join-stamped parent records
in a scan payload. This is the independent-reproducibility check for the
F-3 defect class (wrong-resolution) and for edge invention/loss.

Oracle semantics (written fresh, not copied from the engine):
- parent id: name from the record's "name" field when present, else from the
  path segment after the last "node_modules/"; version from the record.
- child resolution: upward walk -- parent_path/node_modules/<name>, then
  each ancestor node_modules level, then the lockfile root.
- root ("") declarations are tracked separately (synthetic root edges).

Exit code 0 iff: 0 wrong, 0 invented, 0 missing, 0 root mismatches, and
every join-stamped parent record is backed by an oracle edge.
"""

import json
import sys
from pathlib import Path

LOCK = Path(sys.argv[1])
CLEAN = Path(sys.argv[2])

lock = json.loads(LOCK.read_text(encoding="utf-8"))
report = json.loads(CLEAN.read_text(encoding="utf-8"))
pkgs = lock.get("packages", {})
lv = lock.get("lockfileVersion")
print(f"lockfileVersion: {lv}  packages: {len(pkgs)}")
if lv not in (2, 3):
    print("FAIL: oracle requires v2/v3")
    sys.exit(2)


def _name_of(path, record):
    n = record.get("name")
    if n:
        return str(n)
    seg = path.rsplit("node_modules/", 1)[-1]
    return seg


def _id(path, record):
    name = _name_of(path, record)
    ver = str(record.get("version") or "")
    return f"pkg:npm/{name}@{ver}" if ver else f"pkg:npm/{name}"


def resolve_child(parent_path, child_name):
    parts = [p for p in parent_path.split("/") if p]
    while True:
        cand = (
            "/".join(parts + ["node_modules", child_name])
            if parts
            else f"node_modules/{child_name}"
        )
        if cand in pkgs:
            return cand
        if not parts:
            return None
        if len(parts) >= 2 and parts[-2] == "node_modules":
            parts = parts[:-2]
        else:
            parts = parts[:-1]


# ---- oracle: parent id -> declared child name -> resolved child ids --------
oracle = {}
root_decls = {}
for path, record in pkgs.items():
    if not isinstance(record, dict):
        continue
    deps = record.get("dependencies")
    if not isinstance(deps, dict):
        continue
    if path == "":
        root_decls = {str(k) for k in deps}
        continue
    pid = _id(path, record)
    slot = oracle.setdefault(pid, {})
    for child_name in deps:
        cname = str(child_name)
        cpath = resolve_child(path, cname)
        if cpath is None:
            slot.setdefault(cname, set()).add(None)  # unresolvable declaration
            continue
        slot.setdefault(cname, set()).add(_id(cpath, pkgs.get(cpath) or {}))

# ---- engine edges from the payload -----------------------------------------
eng = {}
eng_root = set()
for e in report["dependency_graph"]["edges"]:
    p, c = str(e["parent"]), str(e["child"])
    if p == "pkg:npm/__root__":
        eng_root.add(c)
        continue
    eng.setdefault(p, set()).add(c)

wrong = invented = missing = 0
wrong_samples, invented_samples, missing_samples = [], [], []
for pid, decls in oracle.items():
    got = eng.get(pid, set())
    for cname, cids in decls.items():
        if None in cids and len(cids) == 1:
            continue  # unresolvable declaration; engine skips it too
        hit = got & cids
        if not hit:
            missing += 1
            if len(missing_samples) < 5:
                missing_samples.append((pid, cname, sorted(cids)))
        for c in got:
            cname_got = c.rsplit("pkg:npm/", 1)[-1].rsplit("@", 1)[0]
            if cname_got != cname:
                continue  # different declared name entirely -> invented below
            if c not in cids:
                wrong += 1
                if len(wrong_samples) < 5:
                    wrong_samples.append((pid, cname, c, sorted(cids)))
for pid, got in eng.items():
    decls = oracle.get(pid)
    if decls is None:
        invented += len(got)
        if len(invented_samples) < 5:
            invented_samples.append((pid, sorted(got)))
        continue
    for c in got:
        cname = c.rsplit("pkg:npm/", 1)[-1].rsplit("@", 1)[0]
        if cname not in decls:
            invented += 1
            if len(invented_samples) < 5:
                invented_samples.append((pid, c))

# ---- root edges -------------------------------------------------------------
root_resolved = set()
for cname in root_decls:
    cpath = resolve_child("", cname)
    if cpath:
        root_resolved.add(_id(cpath, pkgs.get(cpath) or {}))
root_mismatch = len(root_resolved ^ eng_root)

# ---- join stamps backed by oracle edges -------------------------------------
sb = report.get("sbom", [])
unstamped = []
for p in sb:
    par = p.get("parent")
    if not par:
        continue
    # join parent stamps are "name@version" (not purls) -> normalize
    pname, _, pver = str(par).rpartition("@")
    pid = f"pkg:npm/{pname}@{pver}"
    cname = str(p.get("name"))
    cid = f"pkg:npm/{cname}@{p.get('version')}"
    decls = oracle.get(pid) or {}
    if cid not in decls.get(cname, set()):
        unstamped.append((pid, cname, p.get("version")))

print(f"oracle parents: {len(oracle)}  root declarations: {len(root_decls)}")
print(f"engine parents: {len(eng)}  root edges: {len(eng_root)}")
print(f"WRONG resolutions:  {wrong}  {wrong_samples}")
print(f"INVENTED edges:     {invented}  {invented_samples}")
print(f"MISSING edges:      {missing}  {missing_samples}")
print(f"ROOT mismatches:    {root_mismatch}")
print(f"JOIN stamps unbacked: {len(unstamped)}  {unstamped}")
ok = wrong == invented == missing == root_mismatch == len(unstamped) == 0
print("ORACLE RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
