"""T-6.1: External attack-surface management (ASM) -- PHASE 6 entry point.

``hashing``   murmur3_32 + Shodan-recipe favicon hash (pure);
``dnsx``      minimal DNS wire codec + subdomain brute (network edge
              is one injectable ``send``; codec is pure bytes-in/out);
``ctlog``     Certificate Transparency parse/merge (pure) + injectable
              crt.sh fetch; passive DNS is a declared connector slot
              (no default provider -- never invented);
``ports``     bounded TCP connect scan (injectable connector, caps
              disclosed);
``tlsinfo``   certificate inventory + expiry grade (pure ``analyze_cert``
              with injected ``as_of`` clock; crypto-optional);
``fingerprint`` tech signatures from response headers/body (pure);
``favicon``   icon link extraction (HTMLParser) + correlation record;
``takeover``  subdomain-takeover CNAME/body fingerprints (pure match,
              confirmed needs BOTH signals on the same provider);
``adminpaths`` exposed admin panel paths + response classification
              (pure; bounded curated list);
``storage``   cloud-storage candidate derivation + posture classify
              (pure; tokens come from the target's own labels);
``collect``   orchestration -> additive ``rsecopsx.asm_inventory/v1``
              artifact + CLI.  Every network stage opt-in/injectable;
              default run does zero I/O and is byte-identical.
"""
from analysis.asm.adminpaths import (  # noqa: F401
    ADMIN_PATHS,
    admin_paths,
    classify_admin_response,
)
from analysis.asm.collect import ASM_SCHEMA, build_inventory, main  # noqa: F401
from analysis.asm.ctlog import (  # noqa: F401
    fetch_crtsh,
    merge_names,
    parse_crtsh,
)
from analysis.asm.dnsx import (  # noqa: F401
    brute_subdomains,
    build_query,
    parse_response,
    resolve_name,
    udp_send,
)
from analysis.asm.favicon import (  # noqa: F401
    extract_icon_href,
    favicon_record,
)
from analysis.asm.fingerprint import SIGNATURES  # noqa: F401
# NOTE: do NOT bind the `fingerprint` FUNCTION here -- it would shadow
# the `fingerprint` submodule attribute (the same trap as
# analysis.dast.correlate).  Callers use fingerprint.fingerprint().
from analysis.asm.hashing import favicon_hash, murmur3_32  # noqa: F401
from analysis.asm.ports import scan_ports, TOP_PORTS  # noqa: F401
from analysis.asm.storage import (  # noqa: F401
    bucket_candidates,
    classify_storage_response,
)
from analysis.asm.takeover import (  # noqa: F401
    correlate_takeover,
    match_body,
    match_cname,
)
from analysis.asm.tlsinfo import (  # noqa: F401
    analyze_cert,
    probe_certificate,
)
