"""Best-effort CPE 2.3 identifiers for SCA components (gap plan 1.4).

CPE is the NVD's matching vocabulary: emitting one per component lets any
consumer re-query the NVD CPE dictionary and correlate advisories across
tools.  The package -> (vendor, product) mapping cannot be derived from a
lockfile alone -- the manifest records WHAT was installed, not how the NVD
happens to catalogue it -- so this module is CONVENTIONAL, deterministic
and honest about what it cannot know:

* Maven: the group is the vendor (first meaningful segment after the
  ``org``/``com``/``net``/``io`` wrapper), the artifact is the product:
  ``org.apache.logging.log4j:log4j-core`` becomes ``apache:log4j-core``,
  matching the CPE dictionary's own convention for that family.
* npm: ``@scope/name`` becomes ``scope:name`` (the dictionary's convention
  for scoped packages); unscoped packages self-vendor.
* Go: ``github.com/owner/repo[/vN]`` becomes ``owner:repo``.
* PyPI / RubyGems / crates.io / Packagist / NuGet: a curated vendor
  dictionary for the packages that dominate real supply-chain risk;
  a miss falls back to vendor == product.

The fallback is deliberate: a self-vendored CPE is still a valid CPE and
still matches NVD *product* searches, while an INVENTED vendor would make
the name match fail silently.  The purl stays the authoritative identity;
CPE is an additional correlation key.  The version is embedded when known
and ``*`` (ANY) when not.
"""

from __future__ import annotations


# Vendor of last resort knowledge: (ecosystem, lowercase name) -> vendor.
# Only entries whose NVD catalogue vendor is well established belong here;
# everything uncertain self-vendors instead.
_KNOWN_VENDORS = {
    ("pypi", "requests"): "python",
    ("pypi", "urllib3"): "python",
    ("pypi", "django"): "djangoproject",
    ("pypi", "flask"): "palletsprojects",
    ("pypi", "jinja2"): "palletsprojects",
    ("pypi", "werkzeug"): "palletsprojects",
    ("pypi", "click"): "palletsprojects",
    ("pypi", "itsdangerous"): "palletsprojects",
    ("pypi", "markupsafe"): "palletsprojects",
    ("pypi", "pillow"): "python_pillow",
    ("pypi", "lxml"): "lxml_project",
    ("pypi", "cryptography"): "cryptography_io",
    ("pypi", "pyyaml"): "pyyaml",
    ("pypi", "paramiko"): "paramiko",
    ("pypi", "sqlparse"): "sqlparse",
    ("pypi", "tensorflow"): "google",
    ("pypi", "pytorch"): "pytorch",
    ("npm", "express"): "expressjs",
    ("npm", "lodash"): "lodash",
    ("npm", "axios"): "axios",
    ("rubygems", "rails"): "rails",
    ("rubygems", "rack"): "rack",
    ("rubygems", "nokogiri"): "rubyonrails",
    ("nuget", "newtonsoft.json"): "newtonsoft",
    ("crates.io", "serde"): "serde-rs",
    ("crates.io", "tokio"): "tokio-rs",
}

# Maven wrapper segments that are org-shape, not the vendor itself.
_MAVEN_WRAPPER = {"org", "com", "net", "io", "de", "uk", "cn", "edu"}


def _escape(value: str) -> str:
    """Escape a value for a CPE 2.3 formatted string.

    Per the CPE 2.3 specification only backslash, double quote, question
    mark and asterisk need escaping -- the latter two because they are the
    ANY/NA wildcards, and an unescaped one would silently turn a concrete
    version into "all versions".
    """
    out = []
    for ch in value:
        if ch in '\\"?*':
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def _maven_vendor_product(name: str) -> tuple[str, str]:
    group, _, artifact = name.partition(":")
    if not artifact:
        # A bare artifact name with no group carries no vendor information.
        return name.lower(), name.lower()
    segments = [s for s in group.lower().split(".") if s]
    vendor = next(
        (s for s in segments if s not in _MAVEN_WRAPPER),
        segments[-1] if segments else "",
    )
    return vendor or group.lower(), artifact.lower()


def _npm_vendor_product(name: str) -> tuple[str, str]:
    if name.startswith("@") and "/" in name:
        scope, _, package = name.partition("/")
        return scope.lstrip("@").lower(), package.lower()
    return name.lower(), name.lower()


def _go_vendor_product(name: str) -> tuple[str, str]:
    # github.com/owner/repo[/vN] -> (owner, repo)
    segments = name.lower().split("/")
    if len(segments) >= 3:
        product = segments[2]
        # Version suffixes (repo/v2) are not part of the product name.
        if len(segments) >= 4 and segments[3].startswith("v") and \
                segments[3][1:].isdigit():
            pass
        return segments[1], product
    return name.lower(), name.lower()


def derive_vendor_product(name: str, ecosystem: str) -> tuple[str, str]:
    """(vendor, product) for a package, by convention. Never empty."""
    name = str(name or "").strip()
    if not name:
        return "", ""
    eco = str(ecosystem or "").strip().lower()

    if eco == "maven":
        return _maven_vendor_product(name)
    if eco == "npm":
        return _npm_vendor_product(name)
    if eco in {"go", "golang"}:
        return _go_vendor_product(name)

    canonical = {
        "pypi": "pypi", "python": "pypi", "pip": "pypi",
        "rubygems": "rubygems", "gem": "rubygems", "ruby": "rubygems",
        "crates.io": "crates.io", "crates": "crates.io",
        "cargo": "crates.io",
        "packagist": "packagist", "composer": "packagist",
        "nuget": "nuget", ".net": "nuget", "dotnet": "nuget",
    }.get(eco, eco)

    vendor = _KNOWN_VENDORS.get((canonical, name.lower()))
    product = name.lower()
    return (vendor or product), product


def build_cpe(name: str, version: str, ecosystem: str) -> str:
    """CPE 2.3 application-platform identifier for one component.

    Returns ``""`` when there is no name to identify.  A component with an
    unknown version still yields a CPE -- with the ANY wildcard in the
    version field, which is exactly what "some version of this product"
    means in the CPE vocabulary.
    """
    name = str(name or "").strip()
    if not name:
        return ""
    version = str(version or "").strip()
    vendor, product = derive_vendor_product(name, ecosystem)
    if not vendor or not product:
        return ""

    version_field = _escape(version) if version and \
        version.lower() != "unknown" else "*"

    fields = [
        "cpe:2.3", "a",
        _escape(vendor), _escape(product), version_field,
        # update, edition, language, sw_edition, target_sw, target_hw, other
        "*", "*", "*", "*", "*", "*", "*",
    ]
    return ":".join(fields)
