"""Yarn v1 verified-edge extractor (R2.3, evidence tier: constraint-resolvable).

Evidence basis (verified on the R2.3 corpus): a ``yarn.lock v1`` file holds
one entry per resolved package instance, keyed by one or more selectors
(``"@ant-design/colors@^7.0.0", "@ant-design/colors@^7.2.1":``), each entry
carrying the exact ``version`` and per-instance ``dependencies`` /
``optionalDependencies`` declarations (name + constraint). The lockfile
holds the resolved universe, so a declaration that matches EXACTLY ONE
resolved child version is a VERIFIED edge; multiple matches are AMBIGUOUS
(candidates disclosed, never picked); zero matches, non-registry specs, or
constraints this matcher cannot understand are UNRESOLVED. Membership alone
is never an edge.

What the lockfile does NOT record: WHICH child instance a parent binds to
when several resolved versions satisfy the parent's constraint -- the v1
hoisting decision is not preserved in the file. Those declarations stay
AMBIGUOUS; no parent binding is invented (R2 contract §3).

Dialect notes (disclosed in the envelope limitations):
- npm space-separated AND-ranges (``>=4 <5``) are normalized to the shared
  matcher's comma conjunction (``>=4,<5``) LOCALLY here -- ``versions.py``
  itself is untouched, so Poetry/uv semantics cannot shift.
- npm ``x`` wildcards (``1.x``) are normalized to ``1.*``.
- Hyphen ranges (``1.2.3 - 2.3.4``), git/tarball/tag specs and ``npm:``
  alias specs are NOT version ranges: alias targets are resolved, the rest
  are reported UNRESOLVED with the requested spec preserved verbatim.
- Yarn v1 does not write ``peerDependencies`` blocks for most packages;
  peer edges exist only where a block is present. Yarn Berry (v2+)
  lockfiles answer with a disclosed UNSUPPORTED envelope.

FND-03: every slice bound is a named span (analysis.spans).
"""

from __future__ import annotations

import re
from pathlib import Path

from analysis.spans import (WINDOW_1, WINDOW_2, WINDOW_4, WINDOW_5,
                            WINDOW_20, WINDOW_M1)
from analysis.lock_graph import contract
from analysis.lock_graph.versions import satisfies

ENGINE = "YARN_LOCK_GRAPH_V1"
EVIDENCE = "YARN_ENTRY_DEPENDENCIES"
FORMAT_VERSION = "yarn lockfile v1"

_PROP = re.compile(r"^\s{2}(\S+)\s*(.*)$")
_DEP = re.compile(r"^\s{4}(\S+)\s+(.*)$")
_DEP_BLOCKS = ("dependencies", "optionalDependencies", "peerDependencies")
_SCOPE_BY_BLOCK = {"dependencies": "runtime",
                   "optionalDependencies": "optional",
                   "peerDependencies": "peer"}
_NPM_PREFIX_LEN = WINDOW_5        # len("@npm:")
_INDENT_DEP = 4                   # dependency lines sit at 4 spaces


def _split_selectors(key_text: str) -> list:
    """Split an entry header into selector tokens, honouring quotes.

    ``"a@^1.0.0", "b@^2.0.0":`` -> [a@^1.0.0, b@^2.0.0]; an unquoted
    multi-key (rare, hand-edited files) splits the same way because the
    separator ``", "`` cannot occur inside a bare npm selector.
    """
    text = key_text.strip()
    if text.endswith(":"):
        text = text[:WINDOW_M1]
    selectors, current, in_quotes = [], [], False
    for ch in text:
        if ch == '"':
            in_quotes = not in_quotes
            continue
        if ch == "," and not in_quotes:
            selectors.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    tail = "".join(current).strip()
    if tail:
        selectors.append(tail)
    return [s for s in selectors if s]


def _parse_selector(selector: str) -> tuple | None:
    """-> (alias_or_None, real_name, spec) or None when unparseable.

    ``pkg@^1.0.0`` -> (None, pkg, ^1.0.0); ``@scope/pkg@1.2.3`` ->
    (None, @scope/pkg, 1.2.3); ``alias@npm:real@^1.0.0`` -> (alias, real,
    ^1.0.0). The LAST ``@`` separates name from spec; npm specs never
    contain a bare ``@`` to the right of the name (git userinfo forms are
    reported unparseable rather than guessed).
    """
    text = selector.strip()
    alias = None
    npm_at = text.find("@npm:")
    if npm_at >= 0:
        alias = text[:npm_at] or None
        target = _parse_selector(text[npm_at + _NPM_PREFIX_LEN:])
        if target is None:
            return None
        return (alias, target[1], target[2])
    at = text.rfind("@")
    if at <= 0:
        return None
    name, spec = text[:at], text[at + WINDOW_1:]
    if not name or not spec:
        return None
    return (alias, name, spec)


def _normalize_npm_range(spec: str) -> str:
    """Map the npm range dialect onto the shared matcher (disclosed, local).

    - space-separated AND-ranges -> comma conjunctions; commas go ONLY
      between clause boundaries (``>= 1.43.0 < 2`` -> ``>= 1.43.0,<2``),
      never inside a clause -- the shared clause grammar already tolerates
      operator-internal spaces;
    - npm hyphen ranges (``A - B``) expand to ``>=A,<B-next`` / ``>=A,<=B``
      with npm's documented partial-range padding (``2`` -> <3.0.0,
      ``2.3`` -> <2.4.0, full ``2.3.4`` -> <=2.3.4);
    - pure ``x`` wildcards -> ``*`` (``x`` / ``x.x`` / ``1.x`` /
      ``1.2.x`` -> ``*`` / ``1.*`` / ``1.2.*``);
    - everything else passes through unchanged (tags, URLs stay
      unparseable -- reported, never approximated).
    """
    text = str(spec or "").strip()
    if not text or text in ("*", "latest"):
        return text
    out = []
    for branch in text.split("||"):
        branch = branch.strip()
        hyphen = re.search(r"(?<![<>=~^])\s-\s", branch)
        if hyphen:
            lo, hi = (branch[:hyphen.start()].strip(),
                      branch[hyphen.end():].strip())
            hi_next = _next_release(hi)
            branch = (f">={lo},<={hi}" if hi_next is None
                      else f">={lo},<{hi_next}")
        elif re.fullmatch(r"[xX*](\.[xX*])*", branch):
            branch = "*"
        else:
            branch = re.sub(r"\.[xX](\.[xX])?$", ".*", branch)
        if "," not in branch and re.search(r"\s", branch):
            branch = re.sub(r"(?<=[0-9A-Za-z*])\s+(?=[~^<>=!0-9*x])",
                            ",", branch)
        out.append(branch)
    return "||".join(out)


def _next_release(bound: str) -> str | None:
    """Exclusive upper bound for a (possibly partial) npm range endpoint.

    ``2`` -> 3.0.0, ``2.3`` -> 2.4.0; a full three-part version returns
    None (the caller keeps ``<=`` against the exact version). Non-numeric
    endpoints return None as well -- the caller then keeps the raw text
    and the shared matcher reports it honestly.
    """
    parts = str(bound or "").strip().split(".")
    if not parts or not re.fullmatch(r"\d+", parts[0]):
        return None
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return None
    if len(nums) >= 3:
        return None                    # full version: keep <= bound
    nums += [0] * (3 - len(nums))      # 2 -> 2.0.0, 2.3 -> 2.3.0
    nums[len(parts) - WINDOW_1] += WINDOW_1
    return ".".join(str(n) for n in nums)


def _dep_child(name: str, spec: str) -> tuple:
    """Resolve a declaration line -> (child_name, requested_spec, alias).

    Aliased declarations (``alias "npm:real@^1.0.0"``) carry the REAL
    package as the child identity; the alias travels as a qualifier.
    """
    name = name.strip().strip('"')
    spec = spec.strip().strip('"').strip()
    if spec.startswith("npm:"):
        target = _parse_selector(name + "@" + spec)
        if target is not None:
            return (target[1], target[2], name)
    return (name, spec, None)


def extract(lockfile_path: str) -> dict:
    try:
        text = Path(lockfile_path).read_text(encoding="utf-8",
                                             errors="replace")
    except Exception as exc:
        return contract.extraction_result(
            engine=ENGINE, source=str(lockfile_path),
            format_version=FORMAT_VERSION,
            graph_status=contract.EXTRACTION_ERROR, edges=[],
            limitations=[f"yarn.lock read failed: {exc}"])

    lines = text.splitlines()
    if not any(line.startswith("# yarn lockfile v1")
               for line in lines[:WINDOW_4]):
        if any(line.strip() == "__metadata:"
               for line in lines[:WINDOW_20]):
            status, limits = contract.UNSUPPORTED_FORMAT, [
                "Yarn Berry (v2+) lockfile detected (__metadata); only "
                "yarn lockfile v1 is supported in R2.3 -- no edges "
                "fabricated.",
            ]
        else:
            status, limits = contract.UNSUPPORTED_FORMAT, [
                "File is not a 'yarn lockfile v1' lockfile; no edges "
                "fabricated.",
            ]
        return contract.extraction_result(
            engine=ENGINE, source=str(lockfile_path),
            format_version=FORMAT_VERSION, graph_status=status, edges=[],
            limitations=limits)

    # ---- parse entries ------------------------------------------------------
    entries = []
    invalid_records = 0
    seen_keys = set()
    duplicate_entries = 0
    current = None
    block = None
    for raw in lines:
        line = raw.rstrip("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0 and line.endswith(":"):
            key_text = line.strip()[:WINDOW_M1]
            if key_text in seen_keys:
                duplicate_entries += 1
                current, block = None, None
                continue
            seen_keys.add(key_text)
            selectors = [_parse_selector(s)
                         for s in _split_selectors(key_text)]
            if not selectors or any(s is None for s in selectors):
                invalid_records += 1
                current, block = None, None
                continue
            if len({s[1] for s in selectors}) != WINDOW_1:
                # one entry must resolve ONE real identity
                invalid_records += 1
                current, block = None, None
                continue
            current = {
                "key": key_text,
                "selectors": selectors,
                "name": selectors[0][1],
                "aliases": {s[0] for s in selectors if s[0]},
                "version": "",
                "resolved": "",
                "blocks": {},
            }
            entries.append(current)
            block = None
            continue
        if current is None:
            invalid_records += 1
            continue
        if indent == WINDOW_2:
            m = _PROP.match(line)
            if m is None:
                invalid_records += 1
                block = None
                continue
            prop, value = m.group(WINDOW_1), m.group(WINDOW_2).strip()
            if prop.endswith(":"):
                # block openers carry no value; (\S+) greedily ate the colon
                prop = prop[:WINDOW_M1]
                value = ""
            if prop in _DEP_BLOCKS and value in ("", ":"):
                block = prop
                current["blocks"].setdefault(block, [])
                continue
            if (value.startswith('"') and value.endswith('"')
                    and len(value) >= WINDOW_2):
                value = value[WINDOW_1:WINDOW_M1]
            if prop == "version":
                current["version"] = value
            elif prop == "resolved":
                current["resolved"] = value
            block = None
            continue
        if indent == _INDENT_DEP and block:
            m = _DEP.match(line)
            if m is None:
                invalid_records += 1
                continue
            current["blocks"][block].append(
                (m.group(WINDOW_1), m.group(WINDOW_2).strip()))
            continue
        invalid_records += 1

    # ---- universe + edges ---------------------------------------------------
    universe: dict[str, list[str]] = {}
    for entry in entries:
        if entry["name"] and entry["version"]:
            universe.setdefault(entry["name"], []).append(entry["version"])

    edges: list[dict] = []
    duplicate_dropped = 0
    for entry in entries:
        parent_name = entry["name"]
        parent_version = entry["version"]
        if not parent_name or not parent_version:
            # an entry without a resolved version can never be a parent
            invalid_records += 1
            continue
        for block_name, decls in entry["blocks"].items():
            scope = _SCOPE_BY_BLOCK[block_name]
            for dep_name_raw, dep_spec_raw in decls:
                child_name, requested, alias = _dep_child(
                    dep_name_raw, dep_spec_raw)
                location = (f"[{entry['key']}] {block_name} "
                            f"{dep_name_raw.strip()}")
                qualifiers = {
                    "entry_selectors": [
                        f"{((s[0] or '') + '@npm:' if s[0] else '')}"
                        f"{s[1]}@{s[2]}"
                        for s in entry["selectors"]],
                }
                if entry["aliases"]:
                    qualifiers["entry_alias"] = ",".join(
                        sorted(entry["aliases"]))
                if entry["resolved"]:
                    qualifiers["resolved_url"] = entry["resolved"]
                if alias:
                    qualifiers["alias"] = alias

                def _edge(**kwargs):
                    edge = contract.build_edge(
                        ecosystem="npm", source=str(lockfile_path),
                        source_location=location,
                        evidence_source=EVIDENCE, scope=scope,
                        qualifiers=qualifiers, **kwargs)
                    # requested_spec is a contract-schema field the shared
                    # builder does not consume; attach it here so the
                    # declared constraint travels with every edge.
                    edge["requested_spec"] = requested
                    return edge

                candidates = universe.get(child_name, [])
                requested_norm = _normalize_npm_range(requested)
                if not candidates:
                    edges.append(_edge(
                        parent_name=parent_name,
                        parent_version=parent_version,
                        child_name=child_name, child_version="",
                        resolution_status="CHILD_NOT_IN_LOCKFILE"))
                    continue
                # identical versions from duplicate entries are ONE package
                # instance: candidate identity is name@version, so the match
                # set dedupes before the single/multiple decision
                matched = sorted({v for v in candidates
                                  if satisfies(v, requested_norm)})
                if len(matched) == 1:
                    edges.append(_edge(
                        parent_name=parent_name,
                        parent_version=parent_version,
                        child_name=child_name, child_version=matched[0]))
                elif len(matched) > 1:
                    edges.append(_edge(
                        parent_name=parent_name,
                        parent_version=parent_version,
                        child_name=child_name, child_version="",
                        confidence=contract.AMBIGUOUS,
                        ambiguity={"constraint": requested,
                                   "candidates": sorted(matched)},
                        resolution_status="MULTIPLE_CANDIDATES"))
                else:
                    parseable = satisfies("1.0.0", requested_norm) is not None
                    edges.append(_edge(
                        parent_name=parent_name,
                        parent_version=parent_version,
                        child_name=child_name, child_version="",
                        resolution_status=("UNPARSEABLE_CONSTRAINT"
                                           if not parseable
                                           else "NO_MATCHING_VERSION")))

    # identical resolved identities (same parent instance declaring the same
    # child at the same version/confidence) dedupe; the requested_spec is
    # preserved on the surviving edge, so no declaration evidence is lost.
    deduped: dict[tuple, dict] = {}
    for edge in edges:
        key = (edge["parent_name"], edge["parent_version"],
               edge["child_name"], edge.get("child_version") or "",
               edge["confidence"])
        if key in deduped:
            duplicate_dropped += 1
            continue
        deduped[key] = edge

    edges = sorted(deduped.values(), key=lambda e: (
        e["parent_name"], e["parent_version"], e["child_name"],
        e["confidence"], e.get("child_version") or "",
    ))
    verified_status = (contract.VERIFIED_EDGES_AVAILABLE if any(
        e["confidence"] == contract.VERIFIED for e in edges)
        else contract.NO_VERIFIED_EDGES)
    limitations = [
        "yarn.lock records constraints, not parent-bound child instances: "
        "declarations matching several resolved versions stay AMBIGUOUS "
        "(candidates disclosed), never guessed to one instance.",
        "yarn v1 lockfiles do not record peerDependencies blocks for most "
        "packages and carry no per-entry dev evidence: peer edges exist "
        "only where a block is present, and scope=dev is never invented.",
        "npm dialect mapping applied locally: space-separated AND-ranges "
        "-> comma conjunctions, x-wildcards -> '*', npm hyphen ranges -> "
        "comparison conjunctions with npm's partial-range padding; tags, "
        "git/tarball/URL specs and npm: alias specs are preserved "
        "verbatim as requested_spec and reported UNRESOLVED, never "
        "approximated.",
    ]
    tallies = {
        "duplicate_records_dropped": duplicate_dropped,
        "invalid_records": invalid_records,
        "duplicate_entries": duplicate_entries,
    }
    return contract.extraction_result(
        engine=ENGINE, source=str(lockfile_path),
        format_version=FORMAT_VERSION, graph_status=verified_status,
        edges=edges, tallies=tallies, limitations=limitations)
