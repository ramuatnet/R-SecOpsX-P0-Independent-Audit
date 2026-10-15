"""
scanner/manifests/ package
Lockfile parsers for R-SecOpsX SCA ecosystem breadth (Phase 1).

Each parser returns list[dict] with the shape:
    {"name": str, "version": str, "ecosystem": str, "license": str,
     "direct": bool, "manifest_file": str, "manifest_line": int}

Ecosystems covered:
    poetry.lock, Pipfile.lock       -> PyPI
    uv.lock, pyproject.toml         -> PyPI (PEP 621 / PEP 735 / poetry)
    pnpm-lock.yaml, yarn.lock, bun.lock, deno.lock -> npm
    go.mod, go.sum                  -> Go
    Cargo.lock                      -> crates.io (Rust)
    composer.lock                   -> Packagist (PHP)
    Gemfile.lock                    -> RubyGems (Ruby)
    *.csproj / Directory.Packages.props / packages.lock.json -> NuGet
"""
from scanner.manifests.poetry_lock import parse_poetry_lock, parse_pipfile_lock
from scanner.manifests.pyproject_toml import parse_pyproject_toml
from scanner.manifests.uv_lock import parse_uv_lock
from scanner.manifests.nuget_packages import (
    parse_nuget_csproj, parse_nuget_packages_props, parse_nuget_lock,
)
from scanner.manifests.pnpm_lock import parse_pnpm_lock
from scanner.manifests.yarn_lock import parse_yarn_lock
from scanner.manifests.bun_lock import parse_bun_lock, parse_deno_lock
from scanner.manifests.go_mod import parse_go_mod, parse_go_sum
from scanner.manifests.cargo_lock import parse_cargo_lock
from scanner.manifests.composer_lock import parse_composer_lock
from scanner.manifests.gemfile_lock import parse_gemfile_lock

__all__ = [
    "parse_poetry_lock", "parse_pipfile_lock",
    "parse_pyproject_toml", "parse_uv_lock",
    "parse_nuget_csproj", "parse_nuget_packages_props", "parse_nuget_lock",
    "parse_pnpm_lock", "parse_yarn_lock", "parse_bun_lock", "parse_deno_lock",
    "parse_go_mod", "parse_go_sum",
    "parse_cargo_lock",
    "parse_composer_lock",
    "parse_gemfile_lock",
]
