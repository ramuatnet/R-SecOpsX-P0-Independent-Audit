"""SYNTHETIC TEST FIXTURE — an invented "legacy backup" copy.

This file is NOT a historical source file and NOT a copy of any real module.
It is a labelled synthetic stand-in shaped like the real legacy backup copies
(definition-bearing, carrying the privacy entrypoint definition) so the
backup-discovery/exclusion contract tests can assert the exclusion mechanism
honestly. See FIXTURE_PROVENANCE.md.
"""


def enrich_privacy_data_exposure(findings, target=None):
    """SYNTHETIC placeholder for the privacy entrypoint shape.

    Contains no real logic; exists only so the definition-discovery regex
    finds this file, and so its exclusion from the live tree is provable.
    """
    return []
