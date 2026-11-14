""".NET/NuGet verified-edge extractor tests (R2.5b).

Every expected graph is an INDEPENDENT hand-authored expectation -- the
tests never validate the extractor against its own output. ALL fixtures
are SYNTHETIC: the corpus contains ZERO packages.lock.json /
project.assets.json files (verified in the R2.5 survey), so those tiers
are fixture-validated and disclosed; the REAL corpus evidence (1
packages.config, 2 Directory.Packages.props, semantic-kernel's 155 csproj
files) validates the membership/declaration envelopes through the oracle.

Evidence tiers (approved R2.5b scope):
- packages.lock.json ``targets`` -> resolved parent-child evidence:
  each ``Package/Version`` target entry's ``dependencies`` map keys carry
  EXACT resolved child identities (``Child/Version``) -- VERIFIED on
  universe membership, UNRESOLVED on miss. The top-level ``dependencies``
  section is the PROJECT's restore state (types Direct/Transitive/
  CentralTransitive): tallied, never edges. Target frameworks travel as
  qualifiers; runtime assets are counted, not edges.
- project.assets.json ``targets`` -> same resolved shape (dependency
  values are constraint strings; the key carries the exact version).
- packages.config -> flat package list: membership only, NEVER edges.
- Directory.Packages.props -> central package management catalog:
  declarations tallied and disclosed, NEVER edges. csproj files are
  arbitrary-named (not registry-dispatchable by exact filename) and
  remain membership-parser territory -- disclosed.

Scenario classes: direct/transitive chains, multiple parents, multiple
versions, multiple target frameworks, runtime assets, restore-type
tallies, CPM, project-reference skipping, unresolved identities,
structural absence of ambiguity (exact-instance evidence, like pnpm),
malformed, unsupported, duplicates, dispatch, determinism, vocabulary.
"""

import pytest

from analysis.lock_graph import contract
from analysis.lock_graph import registry


def _write(tmp_path, text, name):
    lock = tmp_path / name
    lock.write_text(text, encoding="utf-8")
    return str(lock)


def _verified_pairs(result):
    return {(e["parent_name"], e["parent_version"],
             e["child_name"], e["child_version"])
            for e in result["edges"] if e["confidence"] == "VERIFIED"}


LOCK = """\
{
  "version": 1,
  "dependencies": {
    "net6.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.1, )",
        "resolved": "13.0.1",
        "contentHash": "sha512-abc"
      },
      "Serilog": {
        "type": "Transitive",
        "requested": "[2.12.0, )",
        "resolved": "2.12.0"
      }
    }
  },
  "targets": {
    "net6.0": {
      "Newtonsoft.Json/13.0.1": {
        "type": "package",
        "dependencies": {
          "Microsoft.CSharp/10.0.0": {}
        },
        "contentHash": "sha512-abc"
      },
      "Serilog/2.12.0": {
        "type": "package",
        "dependencies": {
          "Microsoft.CSharp/10.0.0": {},
          "Serilog.Sinks.Console/4.1.0": {}
        }
      },
      "Serilog.Sinks.Console/4.1.0": {
        "type": "package"
      },
      "Microsoft.CSharp/10.0.0": {
        "type": "package"
      }
    }
  }
}
"""


# -- packages.lock.json resolved edges ------------------------------------------
def test_lock_chain_verified_edges(tmp_path):
    result = registry.extract_for_file(
        _write(tmp_path, LOCK, "packages.lock.json"))
    assert result["engine"] == "NUGET_LOCK_GRAPH_V1"
    assert result["graph_status"] == "VERIFIED_EDGES_AVAILABLE"
    assert _verified_pairs(result) == {
        ("Newtonsoft.Json", "13.0.1", "Microsoft.CSharp", "10.0.0"),
        ("Serilog", "2.12.0", "Microsoft.CSharp", "10.0.0"),
        ("Serilog", "2.12.0", "Serilog.Sinks.Console", "4.1.0"),
    }
    edge = next(e for e in result["edges"]
                if e["parent_name"] == "Newtonsoft.Json")
    assert edge["ecosystem"] == "nuget"
    assert edge["parent_purl"] == "pkg:nuget/Newtonsoft.Json@13.0.1"
    assert edge["qualifiers"]["target_framework"] == "net6.0"
    assert edge["fingerprint"].startswith("sha256:")
    assert edge["evidence_source"] == "NUGET_LOCK_TARGETS"


def test_lock_multiple_parents(tmp_path):
    # SYNTHETIC: two parents declare the same child under one TFM
    result = registry.extract_for_file(
        _write(tmp_path, LOCK, "packages.lock.json"))
    csharp_parents = [(e["parent_name"], e["parent_version"])
                      for e in result["edges"]
                      if e["child_name"] == "Microsoft.CSharp"
                      and e["confidence"] == "VERIFIED"]
    assert ("Newtonsoft.Json", "13.0.1") in csharp_parents
    assert ("Serilog", "2.12.0") in csharp_parents


def test_lock_multiple_target_frameworks(tmp_path):
    # SYNTHETIC: the same parent resolved under two TFMs -> two edges,
    # each carrying its own target_framework qualifier
    lock = """\
{
  "version": 1,
  "dependencies": {},
  "targets": {
    "net6.0": {
      "Serilog/2.12.0": {
        "type": "package",
        "dependencies": {
          "Microsoft.CSharp/10.0.0": {}
        }
      },
      "Microsoft.CSharp/10.0.0": {
        "type": "package"
      }
    },
    "net48": {
      "Serilog/2.12.0": {
        "type": "package",
        "dependencies": {
          "Microsoft.CSharp/10.0.0": {}
        }
      }
    }
  }
}
"""
    result = registry.extract_for_file(
        _write(tmp_path, lock, "packages.lock.json"))
    edges = [(e["qualifiers"]["target_framework"], e["child_version"])
             for e in result["edges"] if e["parent_name"] == "Serilog"
             and e["confidence"] == "VERIFIED"]
    assert sorted(edges) == [("net48", "10.0.0"), ("net6.0", "10.0.0")]


def test_lock_runtime_assets_counted_not_edges(tmp_path):
    # SYNTHETIC: runtime-specific assets are files, not package relations
    lock = LOCK.replace(
        '"Microsoft.CSharp/10.0.0": {\n        "type": "package"\n      }',
        '"Microsoft.CSharp/10.0.0": {\n        "type": "package",\n'
        '        "runtimeTargets": {\n'
        '          "runtimes/win/lib/x.dll": {\n'
        '            "assetType": "runtime"\n          }\n        }\n'
        '      }')
    result = registry.extract_for_file(
        _write(tmp_path, lock, "packages.lock.json"))
    assert result["tallies"]["runtime_assets"] >= 1
    names = {(e["parent_name"], e["child_name"])
             for e in result["edges"]}
    assert all("runtimes" not in c for (_p, c) in names)


def test_lock_restore_type_tallies_never_edges(tmp_path):
    # the top-level dependencies section is the PROJECT's restore state:
    # types tallied, never edges (no synthetic root)
    result = registry.extract_for_file(
        _write(tmp_path, LOCK, "packages.lock.json"))
    t = result["tallies"]
    assert t["restore_type_direct"] == 1
    assert t["restore_type_transitive"] == 1
    assert all(e["parent_name"] != "." for e in result["edges"])


def test_lock_project_type_targets_skipped(tmp_path):
    # SYNTHETIC: type=project target entries have no package identity
    lock = LOCK.replace(
        '"Serilog.Sinks.Console/4.1.0": {\n        "type": "package"\n      }',
        '"Serilog.Sinks.Console/4.1.0": {\n        "type": "project"\n      }')
    result = registry.extract_for_file(
        _write(tmp_path, lock, "packages.lock.json"))
    assert all(e["child_name"] != "Serilog.Sinks.Console"
               for e in result["edges"])


def test_lock_missing_identity_unresolved(tmp_path):
    lock = """\
{
  "version": 1,
  "dependencies": {},
  "targets": {
    "net6.0": {
      "App/1.0.0": {
        "type": "package",
        "dependencies": {
          "Ghost.Package/9.9.9": {}
        }
      }
    }
  }
}
"""
    result = registry.extract_for_file(
        _write(tmp_path, lock, "packages.lock.json"))
    assert _verified_pairs(result) == set()
    edge = result["edges"][0]
    assert edge["child_name"] == "Ghost.Package"
    assert edge["confidence"] == "UNRESOLVED"
    assert edge["resolution_status"] == "CHILD_NOT_IN_LOCKFILE"


def test_lock_duplicate_tally_semantics(tmp_path):
    # JSON mapping keys are unique per TFM section: duplicate records are
    # structurally impossible; the tally exists and stays 0
    result = registry.extract_for_file(
        _write(tmp_path, LOCK, "packages.lock.json"))
    assert result["tallies"]["duplicate_records_dropped"] == 0


def test_lock_no_targets_unsupported(tmp_path):
    result = registry.extract_for_file(
        _write(tmp_path, '{\n  "version": 1\n}\n', "packages.lock.json"))
    assert result["graph_status"] == "UNSUPPORTED_FORMAT"
    assert result["edges"] == []


def test_lock_malformed_json_extraction_error(tmp_path):
    result = registry.extract_for_file(
        _write(tmp_path, "{ not json ]", "packages.lock.json"))
    assert result["graph_status"] == "EXTRACTION_ERROR"


# -- project.assets.json ---------------------------------------------------------
ASSETS = """\
{
  "version": 3,
  "dependencies": {
    "Newtonsoft.Json": {
      "type": "Direct",
      "requested": "[13.0.1, )",
      "resolved": "13.0.1"
    },
    "Microsoft.CSharp": {
      "type": "Transitive",
      "requested": "[10.0.0, )",
      "resolved": "10.0.0"
    }
  },
  "targets": {
    ".NETCoreApp,Version=v6.0": {
      "Newtonsoft.Json/13.0.1": {
        "type": "package",
        "dependencies": {
          "Microsoft.CSharp/10.0.0": ">= 10.0.0"
        }
      },
      "Microsoft.CSharp/10.0.0": {
        "type": "package"
      }
    }
  }
}
"""


def test_assets_chain_verified_edges(tmp_path):
    result = registry.extract_for_file(
        _write(tmp_path, ASSETS, "project.assets.json"))
    assert result["engine"] == "NUGET_ASSETS_GRAPH_V1"
    assert _verified_pairs(result) == {
        ("Newtonsoft.Json", "13.0.1", "Microsoft.CSharp", "10.0.0")}
    edge = result["edges"][0]
    # the constraint string is preserved verbatim as requested evidence
    assert edge["requested_spec"] == ">= 10.0.0"
    assert edge["qualifiers"]["target_framework"] == \
        ".NETCoreApp,Version=v6.0"
    t = result["tallies"]
    assert t["restore_type_direct"] == 1
    assert t["restore_type_transitive"] == 1


# -- packages.config membership envelope --------------------------------------------
PACKAGES_CONFIG = """\
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net48" />
  <package id="NUnit" version="3.14.0" targetFramework="net48" />
  <package id="NUnit" version="3.13.0" targetFramework="net472" />
</packages>
"""


def test_packages_config_membership_only_never_edges(tmp_path):
    result = registry.extract_for_file(
        _write(tmp_path, PACKAGES_CONFIG, "packages.config"))
    assert result["engine"] == "NUGET_PACKAGES_CONFIG_V1"
    assert result["graph_status"] == "UNSUPPORTED_FORMAT"
    assert result["edges"] == []
    assert result["membership_packages"] == 3
    assert any("membership" in line for line in result["limitations"])


# -- Directory.Packages.props declarations envelope -----------------------------------
PROPS = """\
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageVersion Include="Serilog" Version="2.12.0" />
    <PackageVersion Update="Serilog" Version="2.13.0" />
  </ItemGroup>
</Project>
"""


def test_props_cpm_catalog_tallied_never_edges(tmp_path):
    result = registry.extract_for_file(
        _write(tmp_path, PROPS, "Directory.Packages.props"))
    assert result["engine"] == "NUGET_PROPS_DECLARATIONS_V1"
    assert result["graph_status"] == "UNSUPPORTED_FORMAT"
    assert result["edges"] == []
    t = result["tallies"]
    assert t["package_version_entries"] == 3
    assert t["cpm_includes"] == 2
    assert t["cpm_updates"] == 1
    assert any("central" in line for line in result["limitations"])


# -- dispatch, determinism, vocabulary ------------------------------------------------
def test_registry_dispatches_nuget_files():
    assert {"packages.lock.json", "project.assets.json", "packages.config",
            "Directory.Packages.props"} <= registry.LOCKFILE_NAMES


def test_run_to_run_determinism(tmp_path):
    a = registry.extract_for_file(_write(tmp_path, LOCK, "packages.lock.json"))
    b = registry.extract_for_file(_write(tmp_path, LOCK, "packages.lock.json"))
    assert a == b


def test_confidence_vocabulary_pinned(tmp_path):
    result = registry.extract_for_file(
        _write(tmp_path, LOCK, "packages.lock.json"))
    for edge in result["edges"]:
        assert edge["confidence"] in (
            contract.VERIFIED, contract.AMBIGUOUS, contract.UNRESOLVED,
            contract.UNSUPPORTED, contract.INVALID)
