"""T-3.1: content-addressed corpus manifest.

WHAT THIS IS
------------
An immutable index over ``tests/vuln-test-corpus/``. Every labelled claim
becomes one entry::

    {id, lang, source, rule_id, expected: TP|FP|FN, line, cwe,
     provenance, fixture_sha256}

``id`` is content-addressed: sha256 over the fixture BYTES plus the claim
fields. Editing a fixture re-addresses every one of its entries, so the
manifest cannot keep describing a file that no longer exists -- the exact
rot ``corpus.py`` guards against on the label side, extended to the index.

THREE EXPECTATION KINDS
-----------------------
TP      the engines must find this claim (a label's expected finding).
FN      a pinned known miss (``tests/replay/known_misses.json``). Annotated,
        never deleted: the corpus still scores the miss, and the replay
        fails when a rule change flips it so the re-pin is deliberate.
FP      one entry per SAFE fixture: any finding on that source is a false
        positive. Safe fixtures carry no expected findings, so without this
        entry their assertion would live only in the golden file.

PROVENANCE
----------
Where the truth came from, per family -- OSV for SCA (with the cache key
the advisory is pinned under), fixture semantics for sast/ai_ml, the
format rule for secrets, configuration semantics for iac, and so on. SCA
entries additionally pin (cve, package, version) so the replay can score
them without the network: ``tools/emit_corpus_manifest.py`` extracts every
corpus package's advisory records from ``data/.vuln_cache.json`` into
``tests/replay/vuln_cache_pinned.json``, which is the "extend the existing
pinned SCA pairs" clause made into a committed, offline-complete store.
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

_LOG = logging.getLogger("rsx.analysis.validation.manifest")

MANIFEST_SCHEMA = "rsecopsx.corpus_manifest/v1"
PIN_CACHE_SCHEMA = "rsecopsx.vuln_cache_pinned/v1"

REPO = Path(__file__).resolve().parents[2]
DEFAULT_CORPUS = REPO / "tests" / "vuln-test-corpus"
DEFAULT_REPLAY_DIR = REPO / "tests" / "replay"
DEFAULT_KNOWN_MISSES = DEFAULT_REPLAY_DIR / "known_misses.json"
DEFAULT_PINNED_CACHE = DEFAULT_REPLAY_DIR / "vuln_cache_pinned.json"
DEFAULT_MANIFEST = DEFAULT_REPLAY_DIR / "manifest.json"
LIVE_CACHE = REPO / "data" / ".vuln_cache.json"

# Families whose second path component is the language/ecosystem directory
# (sast/python, sca/npm, iac/terraform, sbom/maven). The rest carry files
# directly and get their language from the file extension.
_LANG_DIRS = frozenset({"sast", "sca", "iac", "sbom"})
_EXT_LANGS = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".go": "go", ".java": "java", ".rb": "ruby", ".rs": "rust",
    ".php": "php", ".cs": "csharp", ".cpp": "cpp", ".c": "c",
    ".tf": "hcl", ".yaml": "yaml", ".yml": "yaml", ".json": "json",
    ".lock": "lockfile", ".mod": "go", ".txt": "text", ".xml": "xml",
}

# Provenance kind per family. The kinds are a closed vocabulary so a
# consumer can switch on them; adding one is a schema change.
_PROVENANCE_KIND = {
    "sast": "fixture-semantics",
    "ai_ml": "fixture-semantics",
    "secrets": "format-rule",
    "iac": "config-semantics",
    "sca": "OSV",
    "cbom": "crypto-inventory",
    "sbom": "component-inventory",
}


def canonical_json(obj) -> bytes:
    """Byte-stable serialization: sorted keys, LF, trailing newline.

    Every committed artifact in this package is dumped through here, so
    "byte-identical" means exactly what it says on any platform.
    """
    return (json.dumps(obj, sort_keys=True, indent=1, ensure_ascii=True)
            + "\n").encode("utf-8")


def entry_id(source: str, fixture_sha256: str, rule_id: str,
             expected: str, line, cwe, cve=None, package=None,
             version=None) -> str:
    """Content address of one claim: fixture bytes + the claim itself.

    The SCA claim triple (cve, package, version) is part of the identity
    because it IS the claim -- it comes from the label, not from the
    provenance citation. The first replay run caught its absence: 11
    jinja2/pyyaml/requests advisories on one fixture hashed to a single
    address, and the manifest could no longer tell its own entries apart.
    Advisory citation style (which OSV id, which provider) stays out of
    the hash: two manifests asserting the same claim describe the same
    truth even if they cite it differently.
    """
    payload = "\x1f".join([
        "rsecopsx.corpus_entry/v1",
        str(source), str(fixture_sha256), str(rule_id), str(expected),
        str(line if line is not None else ""), str(cwe or ""),
        str(cve or ""), str(package or ""), str(version or ""),
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def lang_of(rel: Path) -> str:
    """Language/ecosystem of a fixture from its position (or extension).

    Derived, never declared in the label: a fixture filed under
    ``sca/npm/`` is an npm case because of where it lives, and the label
    gets no vote.
    """
    parts = rel.parts
    if len(parts) >= 3 and parts[0] in _LANG_DIRS:
        return parts[1]
    return _EXT_LANGS.get(rel.suffix.lower(), rel.suffix.lower().lstrip(".")
                          or "unknown")


def _sha256_file(path: Path) -> str:
    """Fixture content address, newline-normalised.

    The corpus tree mixes LF and CRLF checkouts (core.autocrlf=true
    rewrites text files on the next git touch), and hashing raw bytes
    would re-address every fixture depending on how the clone happened.
    Line endings are not claim content, so they are normalised away
    before hashing; an actual edit still changes the address.
    """
    data = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _known_miss_index(known_misses_path: Path | None) -> dict:
    """(source, rule_id, line) -> reason for every pinned known miss."""
    if known_misses_path is None or not Path(known_misses_path).is_file():
        return {}
    doc = _load_json(Path(known_misses_path))
    if doc.get("schema") != "rsecopsx.known_misses/v1":
        raise ValueError("%s: unknown schema %r"
                         % (known_misses_path, doc.get("schema")))
    index: dict[tuple[str, str, int], str] = {}
    for miss in doc.get("misses") or []:
        key = (str(miss["source"]), str(miss["rule_id"]), int(miss["line"]))
        reason = str(miss.get("reason") or "").strip()
        if not reason:
            raise ValueError("known miss without a reason: %r" % (miss,))
        if key in index:
            raise ValueError("duplicate known miss: %r" % (key,))
        index[key] = reason
    return index


def build_manifest(corpus_root: Path | None = None,
                   known_misses_path: Path | None = DEFAULT_KNOWN_MISSES
                   ) -> dict:
    """Derive the manifest from the corpus labels. Read-only."""
    from analysis.validation.corpus import (
        iter_labelled, validate_ground_truth, GroundTruthError)

    root = Path(corpus_root or DEFAULT_CORPUS)
    misses = _known_miss_index(known_misses_path)
    entries: list[dict] = []

    for path, truth in iter_labelled(root):
        rel = path.relative_to(root)
        source = rel.as_posix()
        family = rel.parts[0] if rel.parts else ""
        lang = lang_of(rel)
        fixture_sha = _sha256_file(path)

        if isinstance(truth, GroundTruthError):
            raise ValueError("unparseable label for %s: %s" % (source, truth))
        problems = validate_ground_truth(truth, path, root)
        if problems:
            raise ValueError("invalid label for %s:\n%s"
                             % (source, "\n".join(problems)))

        expected_findings = truth.get("expected_findings") or []
        if not expected_findings:
            # Safe fixture: any finding here is a false positive.
            entries.append({
                "id": entry_id(source, fixture_sha, "*", "FP", 0, None),
                "lang": lang,
                "source": source,
                "rule_id": "*",
                "expected": "FP",
                "line": 0,
                "cwe": None,
                "fixture_sha256": fixture_sha,
                "provenance": {
                    "kind": "safe-fixture",
                    "note": "any finding on this source is a false positive",
                },
            })
            continue

        for finding in expected_findings:
            rule_id = str(finding.get("rule_id"))
            line = int(finding.get("line") or 0)
            cwe = finding.get("cwe")
            cve = finding.get("cve")
            package = finding.get("package")
            version = finding.get("version")
            miss_reason = misses.get((source, rule_id, line))
            expected = "FN" if miss_reason else "TP"

            provenance: dict = {"kind": _PROVENANCE_KIND.get(family, "label")}
            if miss_reason:
                provenance = {"kind": "known-miss", "reason": miss_reason}
            if family in ("sca", "sbom"):
                # The claim triple stays in provenance even on a known miss
                # so the entry id round-trips from the serialized entry.
                # sbom claims are (package, version) component identities;
                # sca adds the CVE. Without these the replay's assertions
                # could not re-derive the claim's identity kind.
                provenance.update({"cve": cve, "package": package,
                                   "version": version})
            provenance["label"] = source + ".ground_truth.json"

            entries.append({
                "id": entry_id(source, fixture_sha, rule_id, expected,
                               line, cwe, cve, package, version),
                "lang": lang,
                "source": source,
                "rule_id": rule_id,
                "expected": expected,
                "line": line,
                "cwe": cwe,
                "fixture_sha256": fixture_sha,
                "provenance": provenance,
            })

    entries.sort(key=lambda e: (e["source"], e["expected"], e["rule_id"],
                                e["line"], e["id"]))
    doc = {
        "schema": MANIFEST_SCHEMA,
        "corpus": "tests/vuln-test-corpus",
        "entry_count": len(entries),
        "entries": entries,
    }
    _check_no_orphan_misses(misses, entries, root)
    return doc


def _check_no_orphan_misses(misses: dict, entries: list[dict],
                            root: Path) -> None:
    """A pinned miss whose claim vanished must be removed deliberately.

    If the label stopped claiming the (rule, line) -- the fixture was
    rewritten, the finding relabelled -- the pin is describing nothing.
    Failing here forces the re-pin into the same commit as the change,
    which is the annotate-never-delete discipline on the other side.
    """
    pinned = {(e["source"], e["rule_id"], e["line"])
              for e in entries if e["expected"] == "FN"}
    orphans = sorted(set(misses) - pinned)
    if orphans:
        raise ValueError(
            "known misses no longer claimed by any label: %r -- re-pin or"
            " remove them in tests/replay/known_misses.json in the same"
            " commit as the corpus change" % (orphans,))


# --------------------------------------------------------------------------
# Pinned SCA advisory store
# --------------------------------------------------------------------------
def build_pinned_cache(corpus_root: Path | None = None,
                       live_cache_path: Path | None = None) -> dict:
    """Extract every corpus SCA package's advisories from the live cache.

    Keys are derived with the engine's own generate_sbom + cache-key
    functions, so the pin is keyed exactly as query_osv_batch will look it
    up during the replay. A label whose CVE is missing from the live cache
    is a hard error: the claim could not be answered offline, and silently
    shipping a pin that cannot score the corpus is how a gate starts
    passing on nothing.

    Records that fail the engine's own completeness predicate
    (``_cache_record_needs_refresh``) are excluded. query_osv_batch
    answers a key from cache only when EVERY record under it is complete;
    a single minimal PYSEC/OSV-native duplicate disqualifies the whole
    key, and offline that key is dropped entirely (the first replay run
    lost all of jinja2/pyyaml/gin this way while the live gate passed on
    re-queried data). Pinning the records the engine would actually
    accept is what makes the offline answer match the live one; if a
    labelled CVE exists only as an incomplete record, the answerability
    check below fails loudly instead.
    """
    from scanner.sbom import generate_sbom
    from scanner.vulnerability_intel import (
        _cache_key, _cache_record_needs_refresh)

    root = Path(corpus_root or DEFAULT_CORPUS)
    live_path = Path(live_cache_path or LIVE_CACHE)
    live = _load_json(live_path)
    live_entries = live.get("entries") if isinstance(live, dict) else None
    if not isinstance(live_entries, dict):
        raise ValueError("%s: no entries mapping (pre-v4 cache?)" % live_path)

    pinned: dict[str, list] = {}
    for path, truth in _iter_sca_fixtures(root):
        case_dir = path.parent
        packages = generate_sbom(str(case_dir)) or []
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            name = str(pkg.get("name") or "").strip()
            version = str(pkg.get("version") or "").strip()
            ecosystem = str(pkg.get("ecosystem") or "").strip()
            if not name or not version or version.lower() == "unknown":
                continue
            if Path(str(pkg.get("manifest_file") or "")).name != path.name:
                continue
            key = _cache_key(name, version, ecosystem)
            records = live_entries.get(key)
            if isinstance(records, list) and records:
                complete = [r for r in records
                            if isinstance(r, dict)
                            and not _cache_record_needs_refresh(r)]
                if complete and len(complete) < len(records):
                    _LOG.info("%s: pinned %d/%d records (incomplete"
                              " advisories are unanswerable offline)",
                              key, len(complete), len(records))
                if complete:
                    pinned[key] = complete

        # Every CVE the label claims must be answerable from the pin.
        # The advisory records carry no package field -- the package and
        # version live in the cache KEY (Ecosystem|name|version), which is
        # also how query_osv_batch will look the claim up at replay time.
        for finding in (truth.get("expected_findings") or []):
            pkg = str(finding.get("package") or "").strip().lower()
            ver = str(finding.get("version") or "").strip()
            cve = str(finding.get("cve") or "").strip().lower()
            answering = {
                str(r.get("cve")).lower()
                for key, records in pinned.items()
                if key.split("|", 2)[1].strip().lower() == pkg
                and key.split("|", 2)[2].strip() == ver
                for r in records
                if isinstance(r, dict) and r.get("cve")
            }
            if cve not in answering:
                raise ValueError(
                    "label %s claims %s for %s@%s but %s holds no COMPLETE"
                    " record for it (incomplete advisories are excluded"
                    " because the engine refuses them offline) -- refresh"
                    " data/.vuln_cache.json with a live scan, then re-run"
                    " the emitter" % (path.name, cve, pkg, ver,
                                      live_path.name))

    return {
        "schema": PIN_CACHE_SCHEMA,
        "source": "extracted from data/.vuln_cache.json by"
                  " tools/emit_corpus_manifest.py",
        "entries": dict(sorted(pinned.items())),
        # Empty on purpose: timestamps would make the artifact non-
        # reproducible, and offline (live feeds off) age never
        # disqualifies a record anyway.
        "fetched": {},
    }


def _iter_sca_fixtures(root: Path):
    from analysis.validation.corpus import iter_labelled
    for path, truth in iter_labelled(root):
        try:
            parts = path.relative_to(root).parts
        except ValueError:
            continue
        if parts and parts[0] == "sca":
            yield path, truth


# --------------------------------------------------------------------------
# Write / check
# --------------------------------------------------------------------------
def write_manifest(corpus_root: Path | None = None,
                   manifest_path: Path | str = DEFAULT_MANIFEST,
                   pinned_cache_path: Path | str = DEFAULT_PINNED_CACHE,
                   known_misses_path: Path | None = DEFAULT_KNOWN_MISSES,
                   live_cache_path: Path | None = None) -> dict:
    """Build and write manifest + pinned cache; returns the manifest doc."""
    corpus_root = Path(corpus_root or DEFAULT_CORPUS)
    manifest_path = Path(manifest_path)
    pinned_cache_path = Path(pinned_cache_path)

    doc = build_manifest(corpus_root, known_misses_path=known_misses_path)
    pin = build_pinned_cache(corpus_root, live_cache_path=live_cache_path)

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(canonical_json(doc))
    pinned_cache_path.write_bytes(canonical_json(pin))
    _LOG.info("wrote %s (%d entries) and %s (%d packages)",
              manifest_path, doc["entry_count"],
              pinned_cache_path, len(pin["entries"]))
    return doc


def check_committed(corpus_root: Path | None = None,
                    manifest_path: Path | str = DEFAULT_MANIFEST,
                    pinned_cache_path: Path | str = DEFAULT_PINNED_CACHE,
                    known_misses_path: Path | None = DEFAULT_KNOWN_MISSES,
                    live_cache_path: Path | None = None) -> list[str]:
    """Rebuild in memory and byte-compare against the committed artifacts.

    Returns a list of human-readable problems; empty means fresh. This is
    the gate the tests and ci run: an edited label or fixture without a
    re-emitted manifest fails here instead of letting the replay diff
    against an index that no longer describes the corpus.
    """
    problems: list[str] = []
    corpus_root = Path(corpus_root or DEFAULT_CORPUS)
    manifest_path = Path(manifest_path)
    pinned_cache_path = Path(pinned_cache_path)

    try:
        doc = build_manifest(corpus_root,
                             known_misses_path=known_misses_path)
        pin = build_pinned_cache(corpus_root,
                                 live_cache_path=live_cache_path)
    except ValueError as exc:
        return [str(exc)]

    if not manifest_path.is_file():
        problems.append("%s is missing -- run tools/emit_corpus_manifest.py"
                        % manifest_path)
    else:
        want = canonical_json(doc)
        have = manifest_path.read_bytes()
        if want != have:
            problems.append(
                "%s is stale (%d bytes differ from a fresh build) -- run"
                " tools/emit_corpus_manifest.py and commit the result with"
                " your change" % (manifest_path, _count_diff(want, have)))

    if not pinned_cache_path.is_file():
        problems.append("%s is missing -- run tools/emit_corpus_manifest.py"
                        % pinned_cache_path)
    else:
        want = canonical_json(pin)
        have = pinned_cache_path.read_bytes()
        if want != have:
            problems.append(
                "%s is stale (%d bytes differ from a fresh build) -- the"
                " corpus SCA questions no longer match the pinned store"
                % (pinned_cache_path, _count_diff(want, have)))
    return problems


def _count_diff(a: bytes, b: bytes) -> int:
    return sum(1 for x, y in zip(a.splitlines(), b.splitlines()) if x != y) \
        + abs(len(a.splitlines()) - len(b.splitlines()))
