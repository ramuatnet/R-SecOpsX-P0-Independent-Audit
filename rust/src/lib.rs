//! T-1.1: pyo3 bridge -- `scan(root, config) -> FindingsJson`.
//!
//! The finding schema is the existing one (scanner.sast._make_finding):
//! Python precomputes every per-rule static field and ships it in the
//! config; this crate fills only the per-match fields (file, line,
//! snippet, evidence, group_key, language). Rule logic lives in the
//! declarative YAML, never here.

mod config;
mod engine;
mod findings;
mod prefilter;
mod scanner_result;
mod walk;

use pyo3::prelude::*;

use crate::config::{RULE_PROGRAM_SCHEMA, SCAN_CONFIG_SCHEMA};

/// Scan `root` with the rule program in `config_json`.
///
/// Accepts either the raw scan config (literal sets extracted at startup)
/// or the compiled rule program from `compile_rules` -- both produce the
/// same envelope (the prefilter runs one extractor either way).
///
/// Returns the findings envelope as a JSON string:
/// `{"schema": "rsecopsx.rust_findings/v1", "findings": [...], "status": {...}}`.
///
/// Failures are raised as Python exceptions (bad config); degradations
/// (unsupported pattern, skipped file) are DISCLOSED in `status` --
/// never silently dropped.
#[pyfunction]
fn scan(root: &str, config_json: &str) -> PyResult<String> {
    let cfg: config::ScanConfig = serde_json::from_str(config_json).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("invalid scan config: {e}"))
    })?;
    if cfg.schema != SCAN_CONFIG_SCHEMA && cfg.schema != RULE_PROGRAM_SCHEMA {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "unsupported config schema {:?} (want {SCAN_CONFIG_SCHEMA:?} or {RULE_PROGRAM_SCHEMA:?})",
            cfg.schema
        )));
    }
    let envelope = engine::scan_root(root, &cfg);
    serde_json::to_string(&envelope)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("serialize findings: {e}")))
}

/// T-1.3 rule compiler: raw scan config -> rule program.
///
/// Computes every rule's MANDATORY literal set (the prefilter's whole
/// vocabulary) and stamps the program schema, so `scan` never has to
/// extract at startup. Deterministic: same config -> same bytes. Rules
/// whose literals come back empty are unprefilterable and still run on
/// every line (fail-safe, listed in status).
#[pyfunction]
fn compile_rules(config_json: &str) -> PyResult<String> {
    let mut cfg: config::ScanConfig = serde_json::from_str(config_json).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("invalid scan config: {e}"))
    })?;
    if cfg.schema != SCAN_CONFIG_SCHEMA && cfg.schema != RULE_PROGRAM_SCHEMA {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "compile_rules wants schema {SCAN_CONFIG_SCHEMA:?} or {RULE_PROGRAM_SCHEMA:?}, got {:?}",
            cfg.schema
        )));
    }
    for rule in &mut cfg.rules {
        if rule.literals.is_none() {
            rule.literals = Some(prefilter::mandatory_literals(&rule.pattern).unwrap_or_default());
        }
    }
    cfg.schema = RULE_PROGRAM_SCHEMA.to_string();
    serde_json::to_string(&cfg)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("serialize program: {e}")))
}

#[pymodule]
fn rsecopsx_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan, m)?)?;
    m.add_function(wrap_pyfunction!(compile_rules, m)?)?;
    m.add("ENGINE_VERSION", engine::ENGINE_VERSION)?;
    Ok(())
}
