"""
core/config.py — Central branding and tool identity configuration.

Change TOOL_NAME and TOOL_VERSION here to rebrand the entire tool.
All modules import from this file — no other file needs to be edited.
"""

TOOL_NAME    = "R-SecOpsX"
TOOL_VERSION = "v2.1"

# Full display string used in headers, footers, and report metadata
TOOL_FULL    = f"{TOOL_NAME} SAST {TOOL_VERSION}"

# Classification label on every report page
CLASSIFICATION = "CONFIDENTIAL"

# Risk model label (used in Excel Summary and JSON metadata)
RISK_MODEL = f"{TOOL_NAME} Weighted Risk Score {TOOL_VERSION}"
