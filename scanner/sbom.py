"""
scanner/sbom.py  v5

CHANGES (v4 †’ v5):
  1. ADD  pom.xml parser: extracts Maven dependencies (groupId, artifactId, version)
           from Java projects.
  2. ADD  Expanded CVE database with JS ecosystem entries (lodash, axios,
           express, moment, node-fetch, log4j).
  3. FIX  requirements.txt parser now handles extras e.g. Flask[async]==2.0.1
  4. ENH  generate_sbom() returns packages sorted: direct first, then transitive,
           each group alphabetically sorted for consistent report output.
"""
from __future__ import annotations
from scanner.vulnerability_overrides import VULNERABILITY_OVERRIDES
from scanner.vulnerability_intel import (
    ADVISORY_SERVICE_STATUS,
    enrich_packages_with_external_vulns,
)
from analysis.intelligence_provenance import STATIC_REFERENCE
from scanner.manifests import (
    parse_poetry_lock, parse_pipfile_lock,
    parse_pnpm_lock, parse_yarn_lock, parse_bun_lock, parse_deno_lock,
    parse_go_mod, parse_go_sum,
    parse_cargo_lock,
    parse_composer_lock,
    parse_gemfile_lock,
)

# Set when advisory enrichment itself raised, as distinct from the service being
# unreachable (which ADVISORY_SERVICE_STATUS records). Both are disclosures; they
# are kept apart so a report can say which happened.
ADVISORY_ENRICHMENT_ERROR: dict = {}


def advisory_service_status() -> dict:
    """Disclosure block for the external advisory lookup.

    Reports and SBOM artifacts carry this so that "no known vulnerabilities" can
    always be distinguished from "the vulnerability database could not be
    reached". Those are different claims and only one of them is safe to act on.
    """
    status = dict(ADVISORY_SERVICE_STATUS)
    if ADVISORY_ENRICHMENT_ERROR:
        status.update(ADVISORY_ENRICHMENT_ERROR)
    status.setdefault("available", True)
    status.setdefault("source", "OSV")
    status.setdefault(
        "disclosure",
        "external advisory database (OSV); absence of a CVE is not evidence of "
        "absence of a vulnerability",
    )
    return status
import json
import re
import xml.etree.ElementTree as ET
from packaging.version import InvalidVersion, Version
from pathlib import Path

from core.license_catalog import infer_package_license

EXCLUDED_DIRS = {"venv", ".venv", "env", "node_modules", ".git", "dist", "build", "vendor", "target", "__pycache__"}


    

# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

_MAVEN_QUALIFIER_RANK = {
    "alpha": 0,
    "beta": 1,
    "milestone": 2,
    "rc": 3,
    "snapshot": 4,
    "": 5,
    "sp": 6,
}

_MAVEN_QUALIFIER_ALIASES = {
    "a": "alpha",
    "b": "beta",
    "m": "milestone",
    "cr": "rc",
    "ga": "",
    "final": "",
    "release": "",
}


def _maven_tokenize(value: str):
    """
    Tokenize a Maven ComparableVersion-style version.

    Numeric portions remain numeric. Qualifier portions remain
    textual so their Maven ordering can be applied explicitly.
    """
    value = str(value or "").strip().lower()

    if not value:
        return [("num", 0)]

    tokens = []
    current = ""
    current_is_digit = None

    def flush():
        nonlocal current, current_is_digit

        if not current:
            return

        if current_is_digit:
            tokens.append(("num", int(current)))
        else:
            tokens.append(("str", current))

        current = ""
        current_is_digit = None

    for ch in value:
        if ch in ".-_":
            flush()
            continue

        is_digit = ch.isdigit()

        if current_is_digit is not None and is_digit != current_is_digit:
            flush()

        current_is_digit = is_digit
        current += ch

    flush()

    return tokens or [("num", 0)]


def _maven_qualifier_key(value: str):
    """
    Maven qualifier ordering.

    alpha < beta < milestone < rc < snapshot < release < sp
    """
    normalized = _MAVEN_QUALIFIER_ALIASES.get(
        str(value or "").lower(),
        str(value or "").lower(),
    )

    if normalized in _MAVEN_QUALIFIER_RANK:
        return (
            0,
            _MAVEN_QUALIFIER_RANK[normalized],
            "",
        )

    # Unknown qualifiers remain deterministic and conservative.
    return (
        1,
        len(_MAVEN_QUALIFIER_RANK),
        normalized,
    )


def _maven_compare(left: str, right: str) -> int:
    """
    Maven-compatible comparison sufficient for SBOM affected-version
    evaluation.

    Returns:
        -1 when left < right
         0 when left == right
         1 when left > right
    """
    a = _maven_tokenize(left)
    b = _maven_tokenize(right)

    max_len = max(len(a), len(b))

    for index in range(max_len):

        # Missing components behave like Maven's implicit zero/release
        # normalization.
        if index >= len(a):
            ai = ("str", "")
        else:
            ai = a[index]

        if index >= len(b):
            bi = ("str", "")
        else:
            bi = b[index]

        atype, aval = ai
        btype, bval = bi

        # Numeric vs numeric
        if atype == "num" and btype == "num":
            if aval < bval:
                return -1
            if aval > bval:
                return 1
            continue

        # Numeric vs qualifier
        if atype == "num" and btype == "str":
            if bval == "":
                if aval == 0:
                    continue
                return 1

            return 1

        # Qualifier vs numeric
        if atype == "str" and btype == "num":
            if aval == "":
                if bval == 0:
                    continue
                return -1

            return -1

        # Qualifier vs qualifier
        arank = _maven_qualifier_key(aval)
        brank = _maven_qualifier_key(bval)

        if arank < brank:
            return -1

        if arank > brank:
            return 1

    return 0


def _looks_maven_version(value: str) -> bool:
    value = str(value or "").strip().lower()

    return bool(
        re.search(
            r"(?:^|[.\-_])"
            r"(?:snapshot|alpha|beta|milestone|rc|cr|final|ga|release|sp)"
            r"(?:[.\-_]|\d|$)",
            value,
        )
    )


def _lt(
    v: str,
    t: str,
    ecosystem: str = None,
) -> bool:
    """
    Version comparison used by SBOM vulnerability rules.
    """
    try:
        if not str(v or "").strip() or not str(t or "").strip():
            return False

        if not re.search(r"\d", str(v)) or not re.search(r"\d", str(t)):
            return False
        ecosystem_name = str(
            ecosystem or ""
        ).strip().lower()

        if ecosystem_name in {"maven", "java", "jar"}:
            return _maven_compare(v, t) < 0

        # Automatically handle explicit Maven qualifiers even if the
        # caller did not provide an ecosystem.
        if _looks_maven_version(v) or _looks_maven_version(t):
            return _maven_compare(v, t) < 0

        # Preserve existing numeric fallback behavior.
        def _p(s: str) -> tuple:
            s = re.sub(
                r"[^0-9.]",
                "",
                str(s),
            )

            try:
                return tuple(
                    int(x)
                    for x in s.split(".")
                    if x
                )
            except Exception:
                return (0,)

        return _p(v) < _p(t)

    except Exception:
        return False
# ---------------------------------------------------------------------------
# Offline CVE database
# ---------------------------------------------------------------------------

KNOWN_VULNS: dict[str, list[dict]] = {
    # Python
    "flask":      [{"affected": lambda v: _lt(v,"1.1.0"), "cve":"CVE-2018-1000656",
                    "cvss":7.5,"severity":"High","epss":0.012,
                    "description":"Open redirect in Flask < 1.1.0",
                    "nvd":"https://nvd.nist.gov/vuln/detail/CVE-2018-1000656",
                    "fixed":"1.1.0","reachable":True}],
    "jinja2":     [{"affected": lambda v: _lt(v,"2.10.3"), "cve":"CVE-2019-10906",
                    "cvss":8.1,"severity":"High","epss":0.009,
                    "description":"Sandbox escape in Jinja2 < 2.10.3",
                    "nvd":"https://nvd.nist.gov/vuln/detail/CVE-2019-10906",
                    "fixed":"2.10.3","reachable":True},
                   {"affected": lambda v: _lt(v,"2.11.3"), "cve":"CVE-2020-28493",
                    "cvss":7.5,"severity":"High","epss":0.006,
                    "description":"ReDoS in Jinja2 < 2.11.3",
                    "nvd":"https://nvd.nist.gov/vuln/detail/CVE-2020-28493",
                    "fixed":"2.11.3","reachable":False}],
    "werkzeug":   [{"affected": lambda v: _lt(v,"0.15.5"), "cve":"CVE-2019-14806",
                    "cvss":7.5,"severity":"High","epss":0.015,
                    "description":"Predictable PIN in Werkzeug debugger",
                    "nvd":"https://nvd.nist.gov/vuln/detail/CVE-2019-14806",
                    "fixed":"0.15.5","reachable":True}],
    "requests":   [{"affected": lambda v: _lt(v,"2.20.1"), "cve":"CVE-2018-18074",
                    "cvss":9.8,"severity":"Critical","epss":0.042,
                    "description":"Credential exposure via redirect in requests",
                    "nvd":"https://nvd.nist.gov/vuln/detail/CVE-2018-18074",
                    "fixed":"2.20.1","reachable":True}],
    "pyyaml":     [{"affected": lambda v: _lt(v,"5.1"), "cve":"CVE-2017-18342",
                    "cvss":9.8,"severity":"Critical","epss":0.089,
                    "description":"Arbitrary code exec via yaml.load()",
                    "nvd":"https://nvd.nist.gov/vuln/detail/CVE-2017-18342",
                    "fixed":"5.1","reachable":True}],
    "sqlalchemy":  [{"affected": lambda v: _lt(v,"1.3.0"), "cve":"CVE-2019-7548",
                    "cvss":8.1,"severity":"High","epss":0.018,
                    "description":"SQL injection via ORDER BY in SQLAlchemy",
                    "nvd":"https://nvd.nist.gov/vuln/detail/CVE-2019-7548",
                    "fixed":"1.3.0","reachable":True}],
    "cryptography":[{"affected": lambda v: _lt(v,"2.6.1"), "cve":"CVE-2018-10903",
                    "cvss":7.5,"severity":"High","epss":0.007,
                    "description":"GCM nonce reuse in cryptography < 2.6.1",
                    "nvd":"https://nvd.nist.gov/vuln/detail/CVE-2018-10903",
                    "fixed":"2.6.1","reachable":False}],
    "urllib3":    [{"affected": lambda v: _lt(v,"1.24.2"), "cve":"CVE-2019-11324",
                    "cvss":7.5,"severity":"High","epss":0.011,
                    "description":"Certificate verification bypass in urllib3",
                    "nvd":"https://nvd.nist.gov/vuln/detail/CVE-2019-11324",
                    "fixed":"1.24.2","reachable":True}],
    "django":     [{"affected": lambda v: _lt(v,"2.1.0"), "cve":"CVE-2018-14574",
                    "cvss":6.1,"severity":"Medium","epss":0.005,
                    "description":"Open redirect in Django CommonMiddleware",
                    "nvd":"https://nvd.nist.gov/vuln/detail/CVE-2018-14574",
                    "fixed":"2.1.0","reachable":True}],
    "pillow":     [{"affected": lambda v: _lt(v,"6.2.0"), "cve":"CVE-2019-16865",
                    "cvss":7.5,"severity":"High","epss":0.008,
                    "description":"DoS via malformed images in Pillow",
                    "nvd":"https://nvd.nist.gov/vuln/detail/CVE-2019-16865",
                    "fixed":"6.2.0","reachable":False}],
    "paramiko":   [{"affected": lambda v: _lt(v,"2.4.2"), "cve":"CVE-2018-1000805",
                    "cvss":9.8,"severity":"Critical","epss":0.035,
                    "description":"Authentication bypass in Paramiko",
                    "nvd":"https://nvd.nist.gov/vuln/detail/CVE-2018-1000805",
                    "fixed":"2.4.2","reachable":True}],
    # JS / npm
    "lodash":     [{"affected": lambda v: _lt(v,"4.17.21"), "cve":"CVE-2021-23337",
                    "cvss":7.2,"severity":"High","epss":0.021,
                    "description":"Command injection via lodash template < 4.17.21",
                    "nvd":"https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
                    "fixed":"4.17.21","reachable":True}],
    "axios":      [{"affected": lambda v: _lt(v,"0.21.2"), "cve":"CVE-2021-3749",
                    "cvss":7.5,"severity":"High","epss":0.013,
                    "description":"ReDoS in axios < 0.21.2",
                    "nvd":"https://nvd.nist.gov/vuln/detail/CVE-2021-3749",
                    "fixed":"0.21.2","reachable":True}],
    "express":    [{"affected": lambda v: _lt(v,"4.17.3"), "cve":"CVE-2022-24999",
                    "cvss":7.5,"severity":"High","epss":0.010,
                    "description":"Open redirect in express < 4.17.3",
                    "nvd":"https://nvd.nist.gov/vuln/detail/CVE-2022-24999",
                    "fixed":"4.17.3","reachable":True}],
    "moment":     [{"affected": lambda v: _lt(v,"2.29.4"), "cve":"CVE-2022-24785",
                    "cvss":7.5,"severity":"High","epss":0.018,
                    "description":"Path traversal in moment.js < 2.29.4",
                    "nvd":"https://nvd.nist.gov/vuln/detail/CVE-2022-24785",
                    "fixed":"2.29.4","reachable":True}],
    "nodefetch":  [{"affected": lambda v: _lt(v,"2.6.7"), "cve":"CVE-2022-0235",
                    "cvss":6.1,"severity":"Medium","epss":0.008,
                    "description":"Exposure of sensitive information in node-fetch < 2.6.7",
                    "nvd":"https://nvd.nist.gov/vuln/detail/CVE-2022-0235",
                    "fixed":"2.6.7","reachable":False}],
    # Java
    "log4j":      [{"affected": lambda v: _lt(v,"2.17.1","maven"), "cve":"CVE-2021-44228",
                    "cvss":10.0,"severity":"Critical","epss":0.975,
                    "description":"Log4Shell: JNDI injection RCE in log4j2 < 2.17.1",
                    "nvd":"https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                    "fixed":"2.17.1","reachable":True}],
    "spring":     [{"affected": lambda v: _lt(v,"5.3.18","maven"), "cve":"CVE-2022-22965",
                    "cvss":9.8,"severity":"Critical","epss":0.970,
                    "description":"Spring4Shell: RCE in Spring Framework < 5.3.18",
                    "nvd":"https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
                    "fixed":"5.3.18","reachable":True}],
}

TRANSITIVE_DEPS: dict[str, list[str]] = {
    "flask":    ["jinja2", "werkzeug", "itsdangerous", "click", "blinker"],
    "django":   ["sqlparse"],
    "requests": ["urllib3", "certifi"],
    "express":  ["qs", "path-to-regexp"],
}


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _resolve_pinned_version(spec: str) -> str:
    """Return the exact version a requirements line pins, else ``unknown``.

    ``==2.19.1`` -> ``2.19.1``. The specifier operator must not travel with
    the version: it is forwarded verbatim to the advisory query as
    ``version=``, and OSV cannot evaluate ``version="==2.19.1"`` against an
    affected range, so it falls back to *every* advisory ever filed for the
    package. Measured on benchmark ``sca-multilang-2026-10`` that produced 39
    invented CVE attributions (django alone: 35) and a 49.3% CVE precision.

    A range such as ``>=1.0,<2.0`` has no resolved version and must become
    ``unknown``: guessing would query a version the project never pinned, and
    ``unknown`` is skipped by the advisory query entirely -- the safe failure
    mode, because a skipped query costs recall while a wrong query costs
    precision *and* trust.
    """
    raw = str(spec or "").strip()
    if not raw or raw.lower() == "unknown":
        return "unknown"

    # Environment markers and inline comments are not part of the specifier.
    raw = raw.split(";", 1)[0].split("#", 1)[0].strip()
    # Editable / URL / VCS requirements carry no resolvable version.
    if "://" in raw or raw.startswith(("git+", "-e", "-r", "--")):
        return "unknown"

    m = re.fullmatch(r"==\s*([A-Za-z0-9][A-Za-z0-9._+\-]*)", raw)
    if not m:
        return "unknown"

    pinned = m.group(1)
    # ``==2.19.*`` is a partial pin with no single resolvable version.
    if pinned.endswith("*"):
        return "unknown"
    return pinned


# A requirement line that is a local or VCS reference rather than a package name.
# pip accepts "/abs/path", "./rel", "../up", "~/x", and "git+https://..." forms.
# The forms are enumerated separately on purpose. An earlier compressed pattern
# `[/~.]{1,2}[/\\]` could not match an ABSOLUTE POSIX path, because it needs a
# separator immediately after one-or-two of `/~.`, and the next character after
# `/` in "/autogen_python/..." is `a`. That silently turned 12 declared local
# dependencies into skipped lines: the scan completed, so the loss looked handled,
# while each was a dependency absent from the SBOM.
_LOCAL_REQUIREMENT_RE = re.compile(
    r"^(?:"
    r"/"                          # absolute POSIX path
    r"|~/"                         # home-relative
    r"|\.\./"                    # parent-relative
    r"|\./"                       # current-relative
    r"|\."                        # "." on its own, which pip accepts
    r"|[A-Za-z]:[\\/]"           # Windows drive, either slash
    r"|(?:git|hg|svn|bzr)\+"      # VCS URL
    r"|(?:file|https?)://"         # file:// or a bare URL
    r")",
    re.I,
)

# Counter for lines that are neither a package spec nor a recognisable local
# reference. Deliberately a list so the module-level binding is mutable without
# `global`; these lines are skipped rather than guessed into an identity.
_REQUIREMENTS_UNPARSED = [0]


def requirements_unparsed_count() -> int:
    """Lines skipped as unrecognisable. Non-zero means the parser met something
    it does not model, which is reported rather than hidden."""
    return _REQUIREMENTS_UNPARSED[0]


def _parse_requirements(filepath: str) -> list[dict]:
    """Parse requirements*.txt and include manifest location."""
    pkgs = []

    for line_no, line in enumerate(
        Path(filepath).read_text(encoding="utf-8-sig", errors="replace").splitlines(),
        start=1
    ):
        line = line.strip()

        if not line or line.startswith(("#", "-")):
            continue

        line_clean = re.sub(r"\[.*?\]", "", line)

        # A requirement may legitimately be a LOCAL or VCS reference rather than
        # a package name -- pip accepts `/path/to/pkg`, `./pkg`, `-e .`,
        # `git+https://...`. Those lines fail the package-name regex, and the
        # previous code then dereferenced a None match OUTSIDE its guard, raising
        # AttributeError and aborting the entire scan. autogen-main has four such
        # requirements files; the scan exited rc=1 and wrote no artifact at all.
        #
        # Such a line declares a real dependency, so it is RECORDED rather than
        # dropped: dropping it would remove a declared dependency from the SBOM,
        # which is indistinguishable downstream from the dependency being absent.
        # Its ecosystem is "local", not "PyPI", because claiming a PyPI identity
        # for a filesystem path would fabricate a package that does not exist.
        try:
            m = re.match(
                r"^([A-Za-z0-9_\-\.]+)\s*(.*)$",
                line_clean
            )
            if m:
                pkgs.append({
                    "name": m.group(1),
                    "version": _resolve_pinned_version(m.group(2)),
                    "ecosystem": "PyPI",
                    "license": "unknown",
                    "direct": True,
                    "manifest_file": filepath,
                    "manifest_line": line_no,
                })
                continue

            local = _LOCAL_REQUIREMENT_RE.match(line_clean)
            if local:
                pkgs.append({
                    "name": line_clean,
                    "version": "unknown",
                    "ecosystem": "local",
                    "license": "unknown",
                    "direct": True,
                    "local_reference": True,
                    "manifest_file": filepath,
                    "manifest_line": line_no,
                })
                continue

            _REQUIREMENTS_UNPARSED[0] += 1
        except Exception:
            # Fail open per line. A malformed requirement must never abort a scan.
            _REQUIREMENTS_UNPARSED[0] += 1

    return pkgs


def _find_line(filepath: str, needle: str) -> int:
    try:
        for idx, line in enumerate(
            Path(filepath).read_text(encoding="utf-8-sig", errors="replace").splitlines(),
            start=1
        ):
            if needle in line:
                return idx
    except Exception:
        pass

    return 1


def _resolve_npm_version(ver) -> str:
    """Resolve an npm dependency entry to an exact version, else ``unknown``.

    ``package.json`` expresses *ranges* (``^4.17.4``, ``~2.1.3``, ``1.x``);
    only ``package-lock.json`` and ``node_modules`` know the installed
    version. Forwarding a range to the advisory query as ``version=``
    reproduces the requirements.txt defect exactly: OSV cannot evaluate
    ``~2.1.3`` against an affected range, so it falls back to every advisory
    ever filed for the package. Measured on benchmark ``sca-multilang-2026-10``
    that produced 4 invented CVEs, including a false vulnerability match on
    ``ms@2.1.3`` -- a package with zero known CVEs.

    ``unknown`` is skipped by the advisory query entirely, so an unresolved
    range costs recall instead of inventing CVEs. The lockfile pass supplies
    the exact version, and the dedupe in ``generate_sbom`` prefers it.
    """
    raw = str(ver or "").strip()
    if not raw or raw.lower() == "unknown":
        return "unknown"
    # Aliases, URLs and workspace/file references resolve to nothing here.
    if "://" in raw or raw[:4] in {"git+", "npm:", "http"}:
        return "unknown"
    if raw.split("@", 1)[0] != raw and not raw[0].isdigit():
        # ``npm:lodash@^4`` alias form
        return "unknown"

    # An exact pin is major.minor.patch (optionally a pre-release/build).
    # Pre-release and build metadata are separate optional groups:
    # ``1.0.0-alpha+build1`` must match, and ``[-+]`` alone would consume
    # only one of the two, so the fullmatch failed and the version resolved
    # to "unknown" -- a real npm pin was then skipped by the advisory query.
    m = re.fullmatch(r"v?([0-9]+(?:\.[0-9]+){2,}"
                     r"(?:-[A-Za-z0-9.\-]+)?(?:\+[A-Za-z0-9.\-]+)?)", raw)
    if not m:
        return "unknown"
    return m.group(1)


def _parse_package_json(filepath: str) -> list[dict]:
    pkgs = []

    try:
        data = json.loads(Path(filepath).read_text(encoding="utf-8-sig"))
    except Exception:
        return pkgs

    # `data["license"]` is the licence of THIS project, not of its
    # dependencies.  package.json does not record a dependency's licence, and
    # node_modules is in EXCLUDED_DIRS, so every package.json reached here is
    # a project manifest.  It used to be stamped onto all 113 dependencies of
    # juice-shop, which is how the report published MIT for glob, graceful-fs
    # and semver (all ISC) and for typescript (Apache-2.0).  The catalogue in
    # core.license_catalog can only correct a value that is honestly absent,
    # because infer_package_license() returns early on any non-UNKNOWN.

    for section in ("dependencies", "devDependencies"):
        for name, ver in data.get(section, {}).items():

            if isinstance(ver, str):
                version = _resolve_npm_version(ver)
            elif isinstance(ver, dict):
                version = str(
                    ver.get("version")
                    or ver.get("resolved")
                    or ver.get("url")
                    or "unknown"
                )
            else:
                version = str(ver)

            pkgs.append({
                "name": name,
                "version": version,
                "ecosystem": "npm",
                "license": "unknown",
                "direct": True,
                "manifest_file": filepath,
                "manifest_line": _find_line(filepath, name),
            })

    return pkgs

def _parse_package_lock(filepath: str) -> list[dict]:
    """
    Parse package-lock.json and extract exact dependency versions + licenses.
    Falls back to node_modules/<package>/package.json when lockfile license is missing.
    """
    pkgs = []

    try:
        data = json.loads(Path(filepath).read_text(encoding="utf-8-sig"))
    except Exception:
        return pkgs

    packages = data.get("packages", {})

    for pkg_path, meta in packages.items():
        if not pkg_path.startswith("node_modules/"):
            continue

        name = pkg_path.replace("node_modules/", "", 1)
        version = str(meta.get("version") or "unknown")

        license_value = meta.get("license") or meta.get("licenses") or "unknown"

        if isinstance(license_value, list):
            license_value = license_value[0] if license_value else "unknown"

        if isinstance(license_value, dict):
            license_value = (
                license_value.get("type")
                or license_value.get("id")
                or "unknown"
            )

        if str(license_value).lower() == "unknown":
            pkg_json = Path(filepath).parent / pkg_path / "package.json"

            if pkg_json.exists():
                try:
                    pdata = json.loads(pkg_json.read_text(encoding="utf-8-sig"))
                    license_value = pdata.get("license") or "unknown"
                except Exception:
                    pass

        pkgs.append({
            "name": name,
            "version": version,
            "ecosystem": "npm",
            "license": str(license_value),
            "direct": False,
            "manifest_file": filepath,
            "manifest_line": 1,
        })

    return pkgs
    

def _parse_pom_xml(filepath: str) -> list[dict]:
    """
    Parse Maven pom.xml and include manifest location.
    """
    pkgs = []

    try:
        tree = ET.parse(filepath)
        root = tree.getroot()

        ns = re.match(r"\{.*\}", root.tag)
        prefix = ns.group(0) if ns else ""

        # The root <licenses> block describes THIS project, never its
        # dependencies.  It used to be read here and stamped onto every entry
        # below, so a GPL-2.0 project reported all 44 of its Maven
        # dependencies as GPL-2.0 -- including commons-codec and
        # jackson-databind, which are Apache-2.0, and hsqldb, which is
        # BSD-3-Clause.  Maven does not declare a dependency's licence in the
        # consuming pom, so the honest value for a dependency is "unknown",
        # which is what lets core.license_catalog consult its package table.
        # That table is skipped whenever a value is already present
        # (infer_package_license returns early on any non-UNKNOWN), which is
        # exactly why the wrong value could never be corrected downstream.
        #
        # A dependency's licence is simply not knowable from this manifest.

        for dep in root.iter(f"{prefix}dependency"):
            group = dep.find(f"{prefix}groupId")
            artifact = dep.find(f"{prefix}artifactId")
            version = dep.find(f"{prefix}version")

            if artifact is None:
                continue

            group_id = (
                group.text.strip()
                if group is not None and group.text
                else "unknown"
            )

            artifact_id = (
                artifact.text.strip()
                if artifact.text
                else "unknown"
            )

            ver_str = (
                version.text.strip()
                if version is not None and version.text
                else "unknown"
            )

            if ver_str.startswith("${"):
                ver_str = "unknown"

            pkgs.append({
                "name": f"{group_id}:{artifact_id}",
                "version": ver_str,
                "ecosystem": "Maven",
                # "unknown", not the root project's licence -- see the note
                # above.  infer_package_license() fills this from the package
                # catalogue, or leaves it honestly unknown.
                "license": "unknown",
                "direct": True,
                "manifest_file": filepath,
                "manifest_line": _find_line(filepath, artifact_id),
            })

    except Exception:
        pass

    return pkgs
# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------

def _add_transitive(packages: list[dict]) -> list[dict]:
    existing = {p["name"].lower() for p in packages}
    extra = []
    for pkg in list(packages):
        for trans in TRANSITIVE_DEPS.get(pkg["name"].lower(), []):
            if trans not in existing:
                extra.append({
                    "name": trans,
                    "version": "unknown",
                    "ecosystem": pkg.get("ecosystem", "unknown"),
                    "license": "unknown",
                    "direct": False,
                    "manifest_file": pkg.get("manifest_file"),
                    "manifest_line": pkg.get("manifest_line"),
                })
                existing.add(trans)
    return packages + extra


def _normalise(name: str) -> str:
    return name.lower().replace("-", "").replace("_", "").replace(".", "")


# Known typosquat pairs  checked against SBOM package names
_SBOM_TYPOSQUATS: dict[str, str] = {
    "reqests": "requests",    "requets": "requests",
    "reuqests": "requests",   "requestss": "requests",
    "urlib": "urllib",        "djano": "django",
    "diango": "django",       "falsk": "flask",
    "flaks": "flask",         "numpyy": "numpy",
    "nunpy": "numpy",         "panads": "pandas",
    "pands": "pandas",        "paramikoo": "paramiko",
    "pyyamll": "pyyaml",      "cryptograhy": "cryptography",
    "crytography": "cryptography", "colourama": "colorama",
    "pycryto": "pycrypto",    "twilo": "twilio",
    "aiohtpp": "aiohttp",     "boto32": "boto3",
}


def enrich_with_cve(packages: list[dict]) -> list[dict]:
    sbom = []
    for pkg in packages:
        # "Unknown", not the literal "None": "None" is a truthy *string*, so
        # every downstream `x or "Unknown"` guard is defeated and the Python
        # word 'None' prints straight into the report's Severity column.
        entry = {**pkg, "cve": None, "cvss": None, "severity": "Unknown",
                 "nvd": None, "epss": None,
                 "description": "No known vulnerabilities",
                 "fixed_in": None, "reachable": False}
        key = _normalise(pkg["name"])
        ver = pkg.get("version", "unknown")

        for db_key, vulns in KNOWN_VULNS.items():
            if _normalise(db_key) == key and ver != "unknown":
                applicable = [v for v in vulns if v["affected"](ver)]
                if applicable:
                    worst = max(applicable, key=lambda x: x["cvss"])
                    entry.update({
                        "cve":         worst["cve"],
                        "cvss":        worst["cvss"],
                        "severity":    worst["severity"],
                        "nvd":         worst["nvd"],
                        "epss":        worst.get("epss"),
                        "description": worst["description"],
                        "fixed_in":    worst["fixed"],
                        "reachable":   worst.get("reachable", False),
                        # KNOWN_VULNS is a compiled-in snapshot of values NVD
                        # publishes and revises, so cvss/severity must not
                        # travel unlabelled next to EPSS values that already
                        # carry epss_provenance. analysis.intelligence_provenance
                        # closes the vocabulary: anything unlabelled degrades to
                        # NOT_AVAILABLE rather than being passed through, so
                        # only this branch asserts STATIC_REFERENCE.
                        "cvss_provenance": STATIC_REFERENCE,
                        "cvss_method": "STATIC_OFFLINE_CVSS_V1",
                    })
                break
        # Issue 7: flag typosquatted package names as supply chain risk
        pkg_norm = _normalise(pkg["name"])
        legit = _SBOM_TYPOSQUATS.get(pkg["name"].lower())
        if legit:
            entry.update({
                "cve":         "TYPOSQUAT",
                "cvss":        8.0,
                "severity":    "High",
                "epss":        None,
                "description": f"Package name '{pkg['name']}' closely resembles '{legit}' probable typosquatting. Malicious packages execute code on install.",
                "fixed_in":    f"Replace with '{legit}'",
                "reachable":   True,
            })
        sbom.append(entry)
    return sbom

def apply_vulnerability_overrides(packages: list[dict]) -> list[dict]:

    for pkg in packages:

        name = pkg.get("name", "")
        version = str(pkg.get("version", ""))

        overrides = VULNERABILITY_OVERRIDES.get(name, [])

        matched = []

        for item in overrides:

            affected = item.get("affected", [])

            if (
                "*" in affected
                or version in affected
                or version == item.get("version")
            ):

                matched.append(item)

        if matched:

            worst = max(
                matched,
                key=lambda x: float(x.get("cvss", 0))
            )

            
            raw_vuln_id = worst.get("cve")

            if raw_vuln_id and str(raw_vuln_id).upper().startswith("CVE-"):
                pkg["cve"] = raw_vuln_id
                pkg["advisory_id"] = worst.get("advisory_id")
            else:
                pkg["cve"] = None
                pkg["advisory_id"] = raw_vuln_id
            
            pkg["cvss"] = worst.get("cvss")
            pkg["severity"] = worst.get("severity")
            pkg["fixed_in"] = worst.get("fixed_in")
            pkg["description"] = worst.get(
                "description",
                "Matched by local vulnerability override."
            )
            pkg["reachable"] = worst.get("reachable", True)
            pkg["override_source"] = "Local Vulnerability Override"

            # A local override is *additional* knowledge, never a replacement
            # for the advisory set. Assigning `matched` here discarded
            # everything OSV had already returned: on benchmark
            # sca-multilang-2026-10 log4j-core collapsed from 7 CVEs to 2,
            # losing CVE-2021-44832 and CVE-2021-45105. Merge instead, and
            # only let the override own the headline fields.
            merged = list(pkg.get("vulnerabilities") or [])
            seen: set[str] = set()
            for v in merged:
                if not isinstance(v, dict):
                    continue
                # An OSV record is keyed by GHSA-... in ``id`` while the same
                # advisory carries the CVE in ``cve``/``aliases``. Indexing
                # only one of them appends the override as a duplicate.
                for field in ("id", "cve", "advisory_id"):
                    val = str(v.get(field) or "").strip()
                    if val:
                        seen.add(val)
                for alias in v.get("aliases") or []:
                    if str(alias).strip():
                        seen.add(str(alias).strip())

            for item in matched:
                ident = str(item.get("cve") or item.get("advisory_id")
                            or "").strip()
                if ident and ident in seen:
                    continue
                if ident:
                    seen.add(ident)
                merged.append(item)
            pkg["vulnerabilities"] = merged

    return packages
    

# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def generate_sbom(target_path: str) -> list[dict]:
    """
    Locate all dependency manifests under target_path and return enriched SBOM.
    Scans: requirements*.txt, package.json, pom.xml
    ENH #4: output sorted direct-first, then transitive, each group alphabetical.
    """
    target   = Path(target_path)
    packages: list[dict] = []

    for f in target.rglob("requirements*.txt"):
        if not any(p in EXCLUDED_DIRS for p in f.parts):
            packages.extend(_parse_requirements(str(f)))

    for f in target.rglob("package.json"):
        if not any(p in EXCLUDED_DIRS for p in f.parts):
            packages.extend(_parse_package_json(str(f)))
            
    for f in target.rglob("package-lock.json"):
        if not any(p in EXCLUDED_DIRS for p in f.parts):
            packages.extend(_parse_package_lock(str(f)))

    for f in target.rglob("pom.xml"):
        if not any(p in EXCLUDED_DIRS for p in f.parts):
            packages.extend(_parse_pom_xml(str(f)))

    # Phase 1: additional lockfile formats (poetry, pnpm, yarn, bun, deno,
    # go, cargo, composer, gemfile). Each parser returns the same dict shape
    # so the dedupe and transitive logic below applies uniformly.
    _LOCKFILE_PATTERNS = (
        ("poetry.lock", parse_poetry_lock),
        ("Pipfile.lock", parse_pipfile_lock),
        ("pnpm-lock.yaml", parse_pnpm_lock),
        ("yarn.lock", parse_yarn_lock),
        ("bun.lock", parse_bun_lock),
        ("deno.lock", parse_deno_lock),
        ("go.mod", parse_go_mod),
        ("go.sum", parse_go_sum),
        ("Cargo.lock", parse_cargo_lock),
        ("composer.lock", parse_composer_lock),
        ("Gemfile.lock", parse_gemfile_lock),
    )
    for pattern, parser in _LOCKFILE_PATTERNS:
        for f in target.rglob(pattern):
            if not any(p in EXCLUDED_DIRS for p in f.parts):
                packages.extend(parser(str(f)))

    # Deduplicate
    seen: set = set()
    unique: list[dict] = []
    for p in packages:
        k = (p["name"].lower(), p["version"], p["ecosystem"])
        if k not in seen:
            seen.add(k)
            unique.append(p)

    # A manifest can often only express a range (``^4.17.4`` -> ``unknown``)
    # while the lockfile pins the installed version. That is one component,
    # not two: drop the unresolvable copy so the SBOM does not list the
    # package twice, and so the resolved version is what drives the advisory
    # query.
    #
    # The lockfile cannot distinguish a direct dependency from a hoisted
    # transitive one -- it stamps every entry ``direct=False`` -- so carry the
    # manifest's flag across. Without this every top-level npm dependency
    # would silently be reclassified as transitive and re-sorted.
    resolved = {
        (p["name"].lower(), p["ecosystem"])
        for p in unique
        if str(p.get("version") or "unknown") != "unknown"
    }
    declared_direct = {
        (p["name"].lower(), p["ecosystem"])
        for p in unique
        if p.get("direct")
    }
    unique = [
        p for p in unique
        if str(p.get("version") or "unknown") != "unknown"
        or (p["name"].lower(), p["ecosystem"]) not in resolved
    ]
    for p in unique:
        key = (p["name"].lower(), p["ecosystem"])
        if not p.get("direct") and key in declared_direct:
            p["direct"] = True

    return finalize_sbom_packages(unique)


def finalize_sbom_packages(packages: list[dict],
                           add_transitive: bool = True) -> list[dict]:
    """Shared post-inventory enrichment tail.

    Runs the transitive expansion (opt-out), the offline CVE table, external
    advisory enrichment (fail-open with disclosure), vulnerability
    overrides, best-effort CPE stamping, the offline licence catalogue, and
    the direct-first sort.

    generate_sbom() calls this with add_transitive=True. The ``--sbom``
    ingest path (scanner/sbom_reader.py) calls it with
    add_transitive=False: an ingested SBOM is authoritative for WHICH
    components exist, and _add_transitive would inject knowledge-base
    guesses stamped version "unknown" into someone else's inventory.
    Enrichment of the declared members is identical either way, so the two
    paths stay behaviour-identical for everything after membership.
    """
    working = _add_transitive(packages) if add_transitive else packages
    enriched = enrich_with_cve(working)

    # Advisory enrichment is an EXTERNAL dependency. It fails open: an outage,
    # a rate limit, or an intermediary returning HTML costs us CVE data for this
    # run and nothing else. It must never abort the scan, because a scan that dies
    # produces no artifact at all while a scan without CVE data at least produces
    # an inventory -- provided the absence is disclosed, which
    # advisory_service_status() is for.
    #
    # query_osv_batch already tolerates a bad service internally; this second guard
    # covers an unanticipated failure mode in the enrichment itself, which would
    # otherwise take the whole SBOM down with it.
    try:
        enriched = enrich_packages_with_external_vulns(enriched)
    except Exception as exc:  # noqa: BLE001 - deliberate: see docstring
        ADVISORY_ENRICHMENT_ERROR.clear()
        ADVISORY_ENRICHMENT_ERROR.update({
            "available": False,
            "error": f"{type(exc).__name__}: {exc}"[:300],
            "impact": (
                "Packages are listed without external CVE data. Absence of a CVE "
                "for these packages is NOT evidence that they are unaffected."
            ),
        })
        enriched = working
    else:
        ADVISORY_ENRICHMENT_ERROR.clear()

    enriched = apply_vulnerability_overrides(enriched)

    # CPE correlation keys (gap plan 1.4): every named component gets a
    # best-effort CPE 2.3 identifier so consumers can re-query the NVD CPE
    # dictionary. Computed AFTER enrichment/overrides so an override can
    # carry its own authoritative CPE (setdefault: never overwrite).
    from scanner.cpe_builder import build_cpe
    for pkg in enriched:
        if str(pkg.get("name") or "").strip() and not pkg.get("cpe"):
            cpe = build_cpe(pkg.get("name", ""), pkg.get("version", ""),
                            pkg.get("ecosystem", ""))
            if cpe:
                pkg["cpe"] = cpe

    # ENH #4: sort direct first, then transitive, each alphabetically
    enriched.sort(key=lambda p: (0 if p.get("direct", True) else 1,
                                  p.get("name", "").lower()))

    for pkg in enriched:
        pkg["license"] = infer_package_license(
            pkg.get("name", ""),
            pkg.get("license", "unknown")
        )
    return enriched



