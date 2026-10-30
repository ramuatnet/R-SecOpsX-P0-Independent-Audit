"""T-6.2: internal cloud posture (PHASE 6, task.md) -- read-only
connectors for AWS/GCP/Azure, normalized inventory, CIS checks,
public-bucket / encryption / logging posture.

``sigv4``    AWS Signature Version 4 (pure stdlib; pinned against the
             AWS documentation vector);
``client``   bounded transport helpers + auth wrappers (SigV4 / bearer);
             injected ``send`` -- no sockets in this module;
``model``    raw op pages -> uniform resource records (compute /
             storage / network / identity / kms / logging);
``posture``  public-bucket / unencrypted / unlogged rollup (pure);
``cis``      bounded CIS control registry -- every judgement emits
             explanation + evidence + remediation, and missing data is
             an ``insufficient_data`` gap, never a silent pass;
``connect``  op tables + bounded live fetch + offline ingest + CLI.
             Credentials are stage-scoped (task.md risk register):
             NOTHING outside this package reads credential env vars,
             scan mode stays offline.

NOTE: do NOT bind functions whose names collide with submodules here
(the analysis.asm ``fingerprint`` shadowing trap) -- callers use
``model.normalize`` / ``cis.run_checks`` etc.
"""
from analysis.cloud.cis import CHECKS, run_checks  # noqa: F401
from analysis.cloud.connect import (  # noqa: F401
    SCHEMA,
    collect_posture,
    main,
    resolve_credentials,
)
from analysis.cloud.model import RESOURCE_TYPES, normalize  # noqa: F401
from analysis.cloud.posture import rollup  # noqa: F401
from analysis.cloud.sigv4 import sign_request  # noqa: F401
