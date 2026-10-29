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

/// Scan `root` with the rule program in `config_json`.
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
    if cfg.schema != config::SCAN_CONFIG_SCHEMA {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "unsupported config schema {:?} (want {:?})",
            cfg.schema,
            config::SCAN_CONFIG_SCHEMA
        )));
    }
    let envelope = engine::scan_root(root, &cfg);
    serde_json::to_string(&envelope)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("serialize findings: {e}")))
}

#[pymodule]
fn rsecopsx_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan, m)?)?;
    m.add("ENGINE_VERSION", engine::ENGINE_VERSION)?;
    Ok(())
}
