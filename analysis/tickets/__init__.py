"""Ticket integration -- scan findings to tracker-profiled issue drafts.

task.md section 12 PHASE 9 "ticket/webhook integrations".  Pure module
+ CLI; the webhook half already lives in analysis.serve (T-8.2).
See model.py for the contracts.
"""
from analysis.tickets.model import (
    MAX_FINDINGS, PROFILES, SCHEMA, SEVERITIES, build, build_findings,
    issue_for, ticket_key, transitions_for,
)

__all__ = [
    "MAX_FINDINGS", "PROFILES", "SCHEMA", "SEVERITIES", "build",
    "build_findings", "issue_for", "ticket_key", "transitions_for",
]
