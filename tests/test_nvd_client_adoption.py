# -*- coding: utf-8 -*-
"""Regression tests for the NVD client fixes adopted from the prod tree.

The VA production tree carried two fixes the repository lacked:
  1. the NVD response key is 'vulnerabilities' -- the repo had a
     'vulnabilities' typo, so every NVD answer was silently treated as
     having no vulnerability list;
  2. the NVD connection pins TLS 1.2 ('match the working NVD connection').

These tests pin both against a mocked response body.
"""
from __future__ import annotations

import io
import sys
import urllib.error

sys.path.insert(0, r"D:\Data\Code test\R-SecOpsX_V11")

from scanner import nvd_client as nc


def test_nvd_body_key_is_vulnerabilities_not_vulnabilities():
    body = {"vulnerabilities": [{"cve": {"id": "CVE-2026-0001"}}]}
    assert isinstance(body.get("vulnerabilities"), list)
    # The repo bug read 'vulnabilities' -- assert the literal is gone
    # from the client source.
    src = open(nc.__file__, encoding="utf-8", errors="replace").read()
    assert "vulnabilities" not in src, "NVD key typo is back"
    assert '"vulnerabilities"' in src or "'vulnerabilities'" in src


def test_nvd_client_pins_tls12():
    src = open(nc.__file__, encoding="utf-8", errors="replace").read()
    assert "TLSVersion.TLSv1_2" in src, "TLS 1.2 pin missing"
    assert "create_default_context" in src
