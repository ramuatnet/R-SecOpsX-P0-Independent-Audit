"""T-6.3: IAM policy analysis (PHASE 6, task.md) -- over-permissive
grants, wildcard actions, cross-account trust, privilege-escalation
paths, unused permissions.

``policy``      policy documents -> normalized grants (parse, model,
                effective permissions; AWS-managed built-in table for
                exactly-representable policies, unknown attached
                policies disclosed, never silently treated as no
                access);
``escalation``  privilege-escalation graph: stdlib adjacency + bounded
                BFS.  task.md names ``petgraph``; it is NOT adopted --
                the offline no-required-deps invariant outranks a
                graph library (taint_interproc / T-2.1 precedent);
``checks``     the five judgement families -- every finding carries
                explanation + evidence + remediation, missing input is
                an insufficient_data gap, graph caps are disclosed;
``connect``    ingest / bounded live fetch (SigV4 via
                analysis.cloud.client) + CLI.  Credentials are resolved
                ONLY through analysis.cloud.connect.resolve_credentials
                (the single stage-scoped env reader); scan mode stays
                offline.

NOTE: do NOT bind functions whose names collide with submodules here
(the analysis.asm ``fingerprint`` shadowing trap) -- callers use
``policy.build_model`` / ``escalation.build_graph`` etc.
"""
from analysis.iam import checks, escalation, policy  # noqa: F401
from analysis.iam.connect import (  # noqa: F401
    SCHEMA,
    collect_iam,
    main,
    resolve_credentials,
)
