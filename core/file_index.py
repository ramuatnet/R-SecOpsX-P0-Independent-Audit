"""T-0.2 (task.md): the one walk + the shared file index.

    one ``walk(root) -> FileIndex{path, lang, size, mtime, content_hash}``
    consumed by all engines. Replace every ``rglob``/``_iter_files``. One
    ``.sastignore`` evaluation, one ``SKIP_DIRS``.

Before this module existed a single scan fanned out into dozens of
independent ``rglob``/``os.walk`` passes -- sast, sbom (~22 pattern
passes alone), every BOM generator, the IaC quartet, secrets, privacy,
IOC, auth, copyright, the LLM passes, reachability, test-coverage --
each re-stat'ing the same tree and each carrying its own (slightly
different) skip list. A divergence in any one list silently changed what
that engine could see.

The contract:

  * ``walk()`` is the one filesystem walk. A scan runs it exactly once;
    the instrumented count is exposed through ``walk_count()`` and lands
    in ``clean_report.json`` metadata (``metadata.file_index.walks``).
    The acceptance test asserts exactly 1 per scan.
  * ``EXCLUDED_DIRS`` here is the UNION of every scan-path engine's
    historical list (sast, sbom, abom, llm_security, python_reachability,
    security_test_coverage, copyright, auth). Each entry is annotated
    with the engine whose FP class it was added to close. One list means
    no engine can silently regain a file another engine excluded, and no
    engine loses one without the oracle corpora measuring it.
  * ``.sastignore`` is loaded once per scan. Path-shaped rules (containing
    ``/``, or ``dir/`` prefixes) are evaluated at the walk; bare rule-id
    rules stay in the finding-level suppression layer (they suppress ONE
    rule's findings, never a whole file -- excluding a file for them would
    drop unrelated rules' findings).
  * The walk is iterative with a depth cap and cycle detection (the T-0.4
    semantics applied to the filesystem). Depth-capped and cycle-skipped
    paths are COUNTED in the walk report, never silent (ground rule 3).
  * ``content_hash`` is part of the FileIndex contract but is filled
    lazily on first read -- the walk must not read every file up front.
"""
from __future__ import annotations

import fnmatch
import hashlib
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

MAX_DEPTH = 10_000

# Content cache bound: the shared read cache exists so sast + taint + the
# BOM/LLM/secrets passes stop re-reading the same file once per engine; it
# is not a memory leak vector on a multi-GB target. Past the cap, reads go
# straight to disk (correct, just not shared).
_CONTENT_CACHE_CAP = 256 * 1024 * 1024

# ---------------------------------------------------------------------------
# Canonical skip policy -- ONE list (union of every scan-path engine's set).
# ---------------------------------------------------------------------------
EXCLUDED_FILES = {
    "bom.json", "clean_report.json", "scan_manifest.json", "sbom.json", "cbom.json",
    "aibom.json", "mlbom.json", "apibom.json", "abom.json", "sarif.json", "qbom.json",
    # Prefixed artifacts. Matching is by exact filename, lowercased, so a bare
    # "qbom.json" entry does not cover "Security_QBOM.qbom.json" and the scanner
    # reads its own output back as scanned input. Every name main.py writes through
    # output_dir is listed, verified against the write sites rather than assumed.
    "security_qbom.pq.json", "security_qbom.qbom.json",
    "security_cyclonedx.json", "security_report.vex.json",
    "security_spdx.spdx.json", "scan_performance.json",
    # Phase 4: the CycloneDX 1.6 CBOM/AI-BOM artifacts. Same hazard as every
    # entry above -- written into output_dir, then read back as scan input on
    # a re-scan of the same directory.
    "security_cbom.cdx.json", "security_aibom.cdx.json",
    # Phase 5.2/5.4 integration artifacts. The CSV is not a scannable
    # extension but is listed per the "every name main.py writes" convention;
    # the two JSONs ARE a self-scan hazard. They were missed when shipped
    # because their write sites live inside reporting/webhook_export.py
    # (helper-module writes), which the self-scan guard's discovery regex
    # could not see -- the guard now scans reporting/ too.
    "security_jira_import.csv", "security_findings_webhook.json",
    "security_defectdojo_import.json",
    # Phase 5.3: the continuous re-evaluation artifact writes BESIDE a
    # caller-supplied clean_report.json by default, so it can land in a
    # directory that is later re-scanned.
    "security_continuous.json",
    # T-0.1: --explain-drops writes drops.json beside clean_report.json;
    # same self-scan hazard as every entry above.
    "drops.json",
    # DoD --explain-verdict writes verdicts.json beside clean_report.json;
    # same self-scan hazard (caught by test_v11_self_scan_exclusions when
    # the artifact name landed without this entry).
    "verdicts.json",
    # T-9.6 / D-2: --html-embedded writes triage.html beside
    # clean_report.json.  HTML IS a scannable extension (XSS rules), so a
    # re-scan of the output directory would read the SPA as input.
    "triage.html",
    # T-14.3 (task.md section 14 "Observability"): --telemetry writes
    # telemetry.json beside clean_report.json; same self-scan hazard as
    # every entry above (JSON IS re-scannable input).
    "telemetry.json",
}

EXCLUDED_DIRS = {
    ".git", ".svn", "node_modules", "__pycache__", ".tox", "venv", ".venv",
    "env", ".env", "dist", "build", ".cache", "vendor", "third_party", "migrations",
    "reports", "artifacts", "output", "outputs", "coverage", ".pytest_cache",
    # I2 (2026-10-19, prodtest/ethernaut): forge build artifacts live in
    # contracts/out/ and are committed but generated (397 files; 14 FP rows:
    # an IPFS CID as an AWS key, methodIdentifiers as credentials, an ABI
    # "log" function in PROMPT_RESPONSE). Sibling output dirs ("output",
    # "outputs", "artifacts") were already excluded; "out" was not.
    "out",
    # I18 (2026-10-26, aclean report): i18n property bundles under
    # src/main/resources/bundle/ are translation files, not source. Their
    # values contain credential-shaped words ("password", "token", "secret")
    # in 12 languages, producing 64 CONFIG_CONTEXTUAL_CREDENTIAL findings
    # per file. "bundle" is the standard Maven/Gradle location for i18n
    # resource bundles.
    "bundle",
    # ---- T-0.2 union additions (one SKIP_DIRS). Each entry was already
    # excluded by SOME scan-path engine; unifying makes it global. ----
    # abom + llm_security + security_test_coverage + auth: Mercurial VCS.
    ".hg",
    # abom + llm_security + copyright + auth + privacy + reachability:
    # Next.js / Nuxt build output.
    ".next", ".nuxt",
    # sbom + abom + privacy + reachability + copyright + auth + j5:
    # Maven / Cargo / Gradle build output. NOTE (T-0.2 behaviour change,
    # measured + disclosed): sast and secret_intelligence did NOT exclude
    # "target" themselves before T-0.2 -- the one-list invariant makes it
    # global for them too (build output is generated or a copy of tracked
    # resources; I2's forge-"out" FP precedent, generalised).
    "target",
    # python_reachability: quarantine dirs used by fix-tooling sandboxes.
    "quarantine",
    # python_reachability: the repo's own backup/ snapshots (debris, not
    # source; sast did not list it because the self-scan artifact names
    # covered its shape, the call-graph engine needed the dir itself).
    "backup",
    # security_test_coverage + copyright: type-checker / IDE state.
    ".mypy_cache",
    ".idea", ".vscode",
    # auth: legacy Bower packages, Angular CLI build cache.
    "bower_components", ".angular",
}

LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".kt": "kotlin", ".scala": "scala", ".go": "go", ".php": "php",
    ".cs": "csharp", ".vb": "vbnet", ".xml": "xml", ".properties": "properties",
    ".rs": "rust",
    # 2026-10-21 batch-10: railsgoat G15 -- .rb fell through to the bare
    # "rb" fallback, so every ruby-language-gated rule (RUBY_RAILS_SECRET_TOKEN)
    # was dead. Mapping the extension is what activates the langs gate; no
    # other rule lists "ruby" today, so nothing else changes behavior.
    ".rb": "ruby",
    # 2026-10-23 G7: .sol had no mapping (and was not in SCANNABLE_EXT), so
    # Solidity sources never reached the rule loop at all. .erb likewise:
    # Rails templates are where the ERB XSS shape actually lives.
    ".sol": "solidity",
    ".erb": "ruby",
    ".yml": "yaml", ".yaml": "yaml", ".json": "json", ".graphql": "graphql", ".gql": "graphql",
    # T-14.1b long-tail languages (task.md section 14, item 1 remainder).
    # .ex/.pl need the mapping most: the bare-ext fallback yields "ex"/"pl",
    # which never satisfies an langs: ['elixir']/['perl'] gate, so the
    # language rules would stay dead even once the files were scannable.
    # .swift/.dart/.lua/.r map to their own names (fallback already matched,
    # but the FileEntry.lang field and G7-style pairing want the map).
    ".swift": "swift", ".dart": "dart",
    ".ex": "elixir", ".exs": "elixir",
    ".lua": "lua", ".r": "r",
    ".pl": "perl", ".pm": "perl",
}

# ---------------------------------------------------------------------------
# Third-party scanner-result detection (JSON variant moved from
# scanner/sast.py so the walk can apply it once for every engine; sast
# keeps the historical names via aliasing, and keeps its XML variant).
# ---------------------------------------------------------------------------
def _is_scanner_result_json(path: Path) -> bool:
    """True when the file is a SECURITY-SCANNER RESULT export (JSON).

    Third-party scanner exports embed evidence from ELSEWHERE in the repo, so
    findings read off them double-count real findings and invent new ones. The
    aclean corpus carried ``RBI7SASTSBOMSCA-result.json``: 98 rows whose
    snippets are that export's own text, matched again as if it were source.

    Detection is by CONTENT -- the report schema's own markers
    (``metadata.tool`` + ``total_findings`` + a ``findings`` list whose members
    carry ``rule_id``) -- and never by filename, so an application JSON that
    happens to hold a ``findings`` array without the report envelope is still
    scanned. The header read is bounded like the XML variant below.
    """
    if path.suffix.lower() != ".json":
        return False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    # The report envelope: a metadata block naming the tool, a total_findings
    # counter beside it, and a findings array. Requiring BOTH the counter and
    # the tool name keeps a config file that merely mentions "findings" clean.
    if '"total_findings"' not in head and '"scan_date"' not in head:
        return False
    if '"tool"' not in head:
        return False
    if '"findings"' not in head and '"secret-id"' not in head:
        return False
    # Corroborate the findings-array member shape: rule_id is the one key every
    # finding carries and no benign config file does. Secrets exports carry
    # secret-id instead (the VA combined export's row shape).
    return '"rule_id"' in head or '"secret-id"' in head


def skip_path(path: Path) -> bool:
    """The canonical skip policy (historical scanner.sast._skip)."""
    excluded_files = {str(name).lower() for name in EXCLUDED_FILES}
    excluded_dirs = {str(name).lower() for name in EXCLUDED_DIRS}
    if (
        path.name.lower() in excluded_files
        or any(str(part).lower() in excluded_dirs for part in path.parts)
        # I19 (2026-10-26, aclean): a scanner-result JSON export inside the
        # tree is tool output, not source. 98 rows on the aclean corpus came
        # from reading one export's own evidence back as code.
        or _is_scanner_result_json(path)
    ):
        return True
    return False


# ---------------------------------------------------------------------------
# .sastignore: ONE load per scan, shared with the accuracy layer.
# ---------------------------------------------------------------------------
_SASTIGNORE_CACHE: "dict[str, list[str]]" = {}
_SASTIGNORE_LOCK = threading.Lock()


def _load_sastignore_rules(target) -> "list[str]":
    """Load <target>/.sastignore once per scan (cached across calls)."""
    if not target:
        return []
    key = os.path.realpath(str(target))
    with _SASTIGNORE_LOCK:
        hit = _SASTIGNORE_CACHE.get(key)
    if hit is not None:
        return hit
    p = Path(target) / ".sastignore"
    rules: "list[str]" = []
    if p.is_file():
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rules.append(line)
    with _SASTIGNORE_LOCK:
        _SASTIGNORE_CACHE[key] = rules
    return rules


def _is_path_rule(pat: str) -> bool:
    """A .sastignore rule that names a LOCATION (walk-time exclusion).

    ``dir/`` prefixes and anything containing a path separator are path
    rules. Bare identifiers (``GENERIC_API_KEY_PASSWORD``) are rule ids and
    stay in the finding-level suppression layer: excluding a whole file for
    a rule id would drop every OTHER rule's findings on that file too.
    """
    return "/" in pat or "\\" in pat


def _path_rule_matches(rel_posix: str, rules: "list[str]") -> bool:
    for pat in rules:
        if not _is_path_rule(pat):
            continue
        if pat.endswith("/") and rel_posix.startswith(pat):
            return True
        if "/" in pat and pat in rel_posix:
            return True
    return False


# ---------------------------------------------------------------------------
# FileIndex
# ---------------------------------------------------------------------------
@dataclass
class FileEntry:
    path: Path          # absolute, resolved root
    rel: str            # relative to root, POSIX separators (stable)
    lang: str           # LANG_BY_EXT value, or "" for unmapped
    ext: str            # lowercased suffix ("" when none)
    size: int
    mtime: float
    content_hash: "Optional[str]" = None   # lazy; see FileIndex.content_hash


class FileIndex:
    """Immutable discovery result of one walk(). Engines query, never walk."""

    def __init__(self, root: Path, entries: "list[FileEntry]",
                 walk_report: dict, sastignore_rules: "list[str]") -> None:
        self.root = root
        self.entries = tuple(entries)
        self.walk_report = walk_report
        self.sastignore_rules = tuple(sastignore_rules)
        self._by_path = {e.path: e for e in entries}
        self._content: "dict[Path, bytes]" = {}
        self._content_bytes = 0

    def files(self, *, lang: "str | None" = None,
              exts: "set[str] | None" = None,
              names: "set[str] | None" = None,
              patterns: "set[str] | None" = None,
              pred: "Callable[[Path], bool] | None" = None) -> "list[Path]":
        """Absolute Paths matching every supplied filter.

        Filters AND together; ``exts``, ``names`` and ``patterns`` OR
        together when combined (the sast shape: extension allow-list OR
        exact-name allow-list -- which is how extensionless files like
        Dockerfile enter a scannable set -- OR fnmatch name globs such as
        ``requirements*.txt``).
        """
        out: "list[Path]" = []
        for e in self.entries:
            if lang is not None and e.lang != lang:
                continue
            if exts is not None or names is not None or patterns is not None:
                ok = False
                if exts is not None and e.ext in exts:
                    ok = True
                if names is not None and e.path.name in names:
                    ok = True
                if not ok and patterns is not None:
                    for pat in patterns:
                        if fnmatch.fnmatch(e.path.name, pat):
                            ok = True
                            break
                if not ok:
                    continue
            if pred is not None and not pred(e.path):
                continue
            out.append(e.path)
        return out

    def entry(self, path) -> "FileEntry | None":
        return self._by_path.get(Path(path))

    def read_text(self, path, encoding: str = "utf-8",
                  errors: str = "replace") -> "str | None":
        """Cached read; keys the content cache used by content_hash().

        The cache stores raw *bytes*, not decoded text: one disk read per
        file no matter which engine asks first, then a per-call decode so
        utf-8 / utf-8-sig / errors=ignore callers each keep their own
        contract (keying by decoded text would leak one engine's decoding
        choices into another's).  Bounded by _CONTENT_CACHE_CAP: past the
        cap the read still happens (correctness never depends on the
        cache), it is just not stored.  Thread-safe enough for the scan's
        ThreadPoolExecutor: dict writes are GIL-atomic and a duplicate
        read under race is benign.
        """
        p = Path(path)
        data = self._content.get(p)
        if data is None:
            try:
                data = p.read_bytes()
            except OSError:
                return None
            if self._content_bytes + len(data) <= _CONTENT_CACHE_CAP:
                self._content[p] = data
                self._content_bytes += len(data)
        # Universal newlines, same as the text-mode open() every replaced
        # read site used (Path.read_text maps \r\n and lone \r to \n).
        # DVWA medium.php is the worked example: with CRLF preserved the
        # $id assignment sits 1501 bytes before the line-55 sink, one byte
        # outside _php_sql_intermediate_query's 1500-char window, and the
        # finding silently dies -- decode-without-normalize was a parity
        # break the moment sast read through the cache. content_hash()
        # still hashes the raw bytes: normalization is a text-view
        # contract, not a file-identity one.
        return data.decode(encoding, errors).replace("\r\n", "\n").replace("\r", "\n")

    def content_hash(self, path) -> "str | None":
        """Lazy sha256 of the file bytes; fills the entry's field."""
        p = Path(path)
        e = self._by_path.get(p)
        if e is None:
            return None
        if e.content_hash is not None:
            return e.content_hash
        data = self._content.get(p)
        if data is None:
            try:
                data = p.read_bytes()
            except OSError:
                return None
            if self._content_bytes + len(data) <= _CONTENT_CACHE_CAP:
                self._content[p] = data
                self._content_bytes += len(data)
        e.content_hash = hashlib.sha256(data).hexdigest()
        return e.content_hash


def read_source(path, encoding: str = "utf-8",
                errors: str = "replace") -> "str | None":
    """The shared read every engine uses during a scan.

    Serves from the scan's index content cache when the path is indexed
    (so sast + taint + BOM + LLM + secrets passes stop re-opening the same
    file once per engine); standalone callers -- tests, offline scripts,
    engines invoked without an active scan -- fall back to a direct read.
    """
    p = Path(path)
    idx = current()
    if idx is not None and idx.entry(p) is not None:
        return idx.read_text(p, encoding=encoding, errors=errors)
    try:
        return p.read_text(encoding=encoding, errors=errors)
    except OSError:
        return None


# ---------------------------------------------------------------------------
# The one walk
# ---------------------------------------------------------------------------
_WALK_LOCK = threading.Lock()
_WALK_COUNT = 0
_CURRENT: "FileIndex | None" = None


def begin_scan() -> None:
    """Reset per-scan state: walk counter, current index, .sastignore cache."""
    global _WALK_COUNT, _CURRENT
    with _WALK_LOCK:
        _WALK_COUNT = 0
        _CURRENT = None
    with _SASTIGNORE_LOCK:
        _SASTIGNORE_CACHE.clear()


def walk_count() -> int:
    with _WALK_LOCK:
        return _WALK_COUNT


def current() -> "FileIndex | None":
    with _WALK_LOCK:
        return _CURRENT


def set_current(index: "FileIndex | None") -> None:
    global _CURRENT
    with _WALK_LOCK:
        _CURRENT = index


def index_for(root) -> FileIndex:
    """The index engines consume: the scan's current index when the root
    matches, else a fresh walk (standalone engine runs, validation
    harnesses, tests). Never a second walk of the scan root."""
    resolved = Path(root).resolve()
    cur = current()
    if cur is not None and cur.root == resolved:
        return cur
    return walk(root)


def _entry_for(path: Path, root: Path) -> FileEntry:
    stat = path.stat(follow_symlinks=True)
    ext = path.suffix.lower()
    return FileEntry(
        path=path,
        rel=Path(os.path.relpath(path, root)).as_posix(),
        lang=LANG_BY_EXT.get(ext, ""),
        ext=ext,
        size=stat.st_size,
        mtime=stat.st_mtime,
    )


def walk(root, *, max_depth: int = MAX_DEPTH) -> FileIndex:
    """The one filesystem walk. Iterative, depth-capped, cycle-detected."""
    global _WALK_COUNT, _CURRENT
    root_path = Path(root)
    report = {
        "files": 0,
        "dirs_excluded": 0,
        "dirs_outside_root": 0,
        "files_outside_root": 0,
        "files_excluded_name": 0,
        "sastignore_skipped": 0,
        "scanner_result_skipped": 0,
        "depth_capped": 0,
        "cycles_detected": 0,
    }
    rules = _load_sastignore_rules(root_path if root_path.is_dir()
                                   else root_path.parent)
    entries: "list[FileEntry]" = []

    if root_path.is_file():
        # An explicit file target (e.g. --sbom ingest) is requested by the
        # user: include it unconditionally, no policy veto.
        entries.append(_entry_for(root_path.resolve(), root_path.resolve()))
    elif root_path.is_dir():
        root_res = root_path.resolve()
        root_norm = os.path.normcase(os.path.realpath(root_res))
        excluded_dirs = {str(d).lower() for d in EXCLUDED_DIRS}
        excluded_files = {str(f).lower() for f in EXCLUDED_FILES}
        stack: "list[tuple[Path, int]]" = [(root_res, 0)]
        seen_dirs: "set[str]" = {root_norm}
        while stack:
            dirpath, depth = stack.pop()
            try:
                with os.scandir(dirpath) as it:
                    kids = sorted(it, key=lambda d: d.name)
            except OSError:
                continue
            files_here: "list[os.DirEntry]" = []
            dirs_here: "list[os.DirEntry]" = []
            for de in kids:
                try:
                    # Follow dir symlinks (parity with the rglob behaviour
                    # every engine used to have); the containment check
                    # below keeps an escaping link from dragging the rest
                    # of the disk into the scan, and the seen-set breaks
                    # symlink loops.
                    if de.is_dir(follow_symlinks=True):
                        dirs_here.append(de)
                    elif de.is_file(follow_symlinks=True):
                        files_here.append(de)
                except OSError:
                    continue
            for de in files_here:
                p = Path(de.path)
                if p.name.lower() in excluded_files:
                    report["files_excluded_name"] += 1
                    continue
                if de.is_symlink():
                    # A symlinked file whose target escapes the scan root is
                    # not part of the scanned tree (resource-bound: a link to
                    # C:\ would otherwise drag the world into the scan).
                    try:
                        link_n = os.path.normcase(os.path.realpath(p))
                    except OSError:
                        continue
                    if link_n != root_norm and not link_n.startswith(
                            root_norm + os.sep):
                        report["files_outside_root"] += 1
                        continue
                if _is_scanner_result_json(p):
                    report["scanner_result_skipped"] += 1
                    continue
                rel = Path(os.path.relpath(p, root_res)).as_posix()
                if _path_rule_matches(rel, rules):
                    report["sastignore_skipped"] += 1
                    continue
                try:
                    entries.append(_entry_for(p, root_res))
                except OSError:
                    continue
            if depth >= max_depth:
                report["depth_capped"] += len(dirs_here)
                continue
            for de in dirs_here:
                if de.name.lower() in excluded_dirs:
                    report["dirs_excluded"] += 1
                    continue
                child = Path(de.path)
                try:
                    real = os.path.realpath(child)
                except OSError:
                    continue
                real_n = os.path.normcase(real)
                # Windows junctions present as ordinary directories (not
                # symlinks); without this check a junction to C:\ drags the
                # whole disk into the scan. iac_terraform pruned this per-
                # engine before -- the one walk applies it everywhere.
                if real_n != root_norm and not real_n.startswith(
                        root_norm + os.sep):
                    report["dirs_outside_root"] += 1
                    continue
                if real_n in seen_dirs:
                    report["cycles_detected"] += 1
                    continue
                seen_dirs.add(real_n)
                stack.append((child, depth + 1))
    else:
        # Nonexistent target: empty index (callers already handle missing
        # targets with their own errors; the walk must not raise here).
        pass

    entries.sort(key=lambda e: e.rel)
    report["files"] = len(entries)
    index = FileIndex(
        root=(root_path.resolve() if root_path.exists() else root_path),
        entries=entries,
        walk_report=report,
        sastignore_rules=rules,
    )
    with _WALK_LOCK:
        _WALK_COUNT += 1
        _CURRENT = index
    return index


def report_metadata(index: "FileIndex | None") -> dict:
    """Deterministic metadata.file_index block for clean_report.json.

    Every field is structural (no wall-clock, no timings): two scans of
    the same tree emit byte-identical blocks (ground rule 10).
    """
    if index is None:
        return {"walks": walk_count(), "files": 0}
    out = {"walks": walk_count()}
    out.update(index.walk_report)
    return out
