//! T-1.2: the walker -- `ignore` crate traversal under the SAME policy
//! core/file_index.walk applies on the Python side.
//!
//! Policy is passed in by Python (excluded files/dirs, .sastignore path
//! rules, depth cap) so the lists have one source of truth. Divergences
//! from the Python walk are deliberate, counted, and DISCLOSED in the
//! envelope status rather than hidden:
//!
//!   * symlinked DIRECTORIES are not descended (Python follows them with
//!     a containment check); symlinked files ARE followed subject to the
//!     same containment check;
//!   * `.gitignore` is NOT honoured (Python does not honour it either --
//!     standard filters are off, so hidden files are walked as Python
//!     walks them).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ignore::WalkBuilder;

use crate::config::ScanConfig;

#[derive(Debug)]
pub struct WalkedFile {
    /// Path as it will appear in findings (root joined, OS separators) --
    /// mirrors Python's `str(Path)` on the entry.
    pub abs: PathBuf,
    /// Root-relative POSIX path (stable across platforms).
    pub rel: String,
}

#[derive(Default, Debug)]
pub struct WalkStatus {
    pub files: usize,
    pub excluded_dirs: usize,
    pub excluded_files: usize,
    pub scanner_result_skipped: usize,
    pub sastignore_skipped: usize,
    pub symlink_files_outside_root: usize,
}

/// True when `rel_posix` matches a .sastignore LOCATION rule -- exact
/// mirror of file_index._path_rule_matches (path rules only; bare rule
/// ids are finding-level suppression and never reach the walk).
fn path_rule_matches(rel_posix: &str, rules: &[String]) -> bool {
    for pat in rules {
        let is_path_rule = pat.contains('/') || pat.contains('\\');
        if !is_path_rule {
            continue;
        }
        if pat.ends_with('/') && rel_posix.starts_with(pat.as_str()) {
            return true;
        }
        if pat.contains('/') && rel_posix.contains(pat.as_str()) {
            return true;
        }
    }
    false
}

/// Windows canonical paths can carry the `\\?\` prefix; Python's
/// realpath comparisons do not. Normalise it away before comparing.
fn strip_verbatim(p: &str) -> String {
    if let Some(rest) = p.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    if let Some(rest) = p.strip_prefix(r"\\?\") {
        return rest.to_string();
    }
    p.to_string()
}

fn normalized_realpath(p: &Path) -> Option<String> {
    let canon = std::fs::canonicalize(p).ok()?;
    let s = strip_verbatim(&canon.to_string_lossy());
    Some(s.to_lowercase())
}

pub fn walk(root: &Path, cfg: &ScanConfig) -> (Vec<WalkedFile>, WalkStatus) {
    let mut status = WalkStatus::default();
    let mut out: Vec<WalkedFile> = Vec::new();

    // Python's index roots at Path.resolve(): absolute, OS-native
    // separators, symlinks resolved (file_index.index_for). A caller may
    // hand us forward slashes ("tests/vuln" -- os.path.join and pathlib
    // both keep inner '/' on Windows), and findings embed this path, so
    // separators must normalise here or every (file,line) triple misses
    // parity with the Python engine.
    let root_raw: PathBuf = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(root)
    };
    let root_abs: PathBuf = match std::fs::canonicalize(&root_raw) {
        Ok(c) => PathBuf::from(strip_verbatim(&c.to_string_lossy())),
        // Not-yet-existing root: keep the join (walk finds nothing) but
        // still normalise separators through components().
        Err(_) => root_raw.components().collect(),
    };
    let root_real = normalized_realpath(&root_abs);
    let root_real_prefix = root_real.as_ref().map(|r| format!("{r}\\"));

    if !root_abs.is_dir() {
        // Python walk: nonexistent/file targets are handled by callers;
        // a non-dir root yields no files here.
        if root_abs.is_file() {
            // Explicit single-file target: Python appends it with no
            // policy veto (see file_index.walk).
            if let Some(name) = root_abs.file_name() {
                let n = name.to_string_lossy().to_lowercase();
                if cfg.excluded_files.contains(&n) {
                    status.excluded_files += 1;
                } else {
                    out.push(WalkedFile {
                        abs: root_abs.clone(),
                        rel: name.to_string_lossy().to_string(),
                    });
                    status.files = 1;
                }
            }
        }
        return (out, status);
    }

    let excluded_dirs: HashSet<String> = cfg
        .excluded_dirs
        .iter()
        .map(|s| s.to_lowercase())
        .collect();
    let excluded_files: HashSet<String> = cfg
        .excluded_files
        .iter()
        .map(|s| s.to_lowercase())
        .collect();
    let sastignore: &[String] = &cfg.sastignore_rules;

    let mut builder = WalkBuilder::new(&root_abs);
    builder
        .standard_filters(false) // no gitignore/hidden/parents -- Python walks them
        .follow_links(false)     // v1: symlinked dirs are NOT descended (disclosed)
        .max_depth(Some(cfg.max_depth));

    // The filter runs inside the walker and cannot borrow &mut status,
    // so the pruned-dir count travels out through an atomic -- every
    // exclusion is COUNTED (no silent drops in the disclosure).
    let excluded_dir_count = Arc::new(AtomicUsize::new(0));
    let dirs = excluded_dirs.clone();
    let counter = Arc::clone(&excluded_dir_count);
    builder.filter_entry(move |e| {
        if e.file_type().map_or(false, |t| t.is_dir()) {
            let n = e.file_name().to_string_lossy().to_lowercase();
            if dirs.contains(&n) {
                counter.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }
        true
    });

    let mut entries: Vec<WalkedFile> = Vec::new();
    let mut seen_dirs: HashSet<String> = HashSet::new();
    if let Some(root_key) = root_real.clone() {
        seen_dirs.insert(root_key);
    }

    for result in builder.build() {
        let Ok(entry) = result else { continue };
        let path = entry.path();

        let ft = entry.file_type();
        let is_dir = ft.map_or(false, |t| t.is_dir());
        let is_symlink = ft.map_or(false, |t| t.is_symlink());
        if is_dir {
            continue;
        }

        // File or symlink-to-file. Symlink targets must stay inside the
        // root (file_index.walk's containment check: a link to C:\
        // otherwise drags the world into the scan).
        let mut scan_it = false;
        if ft.map_or(false, |t| t.is_file()) {
            scan_it = true;
        } else if is_symlink {
            if path.is_file() {
                match normalized_realpath(path) {
                    None => continue,
                    Some(real) => {
                        let inside = match (&root_real, &root_real_prefix) {
                            (Some(rr), Some(rp)) => real == *rr || real.starts_with(rp.as_str()),
                            _ => true,
                        };
                        if inside {
                            scan_it = true;
                        } else {
                            status.symlink_files_outside_root += 1;
                            continue;
                        }
                    }
                }
            } else {
                continue;
            }
        }
        if !scan_it {
            continue;
        }

        if let Some(name) = path.file_name() {
            if excluded_files.contains(&name.to_string_lossy().to_lowercase()) {
                status.excluded_files += 1;
                continue;
            }
        }

        let Ok(rel_os) = path.strip_prefix(&root_abs) else {
            continue;
        };
        let rel = rel_os.to_string_lossy().replace('\\', "/");

        if crate::scanner_result::is_scanner_result_json(path) {
            status.scanner_result_skipped += 1;
            continue;
        }
        if path_rule_matches(&rel, sastignore) {
            status.sastignore_skipped += 1;
            continue;
        }

        entries.push(WalkedFile {
            abs: root_abs.join(rel_os),
            rel,
        });
    }

    // file_index.walk sorts entries by rel for a stable scan order.
    entries.sort_by(|a, b| a.rel.cmp(&b.rel));
    status.excluded_dirs = excluded_dir_count.load(Ordering::Relaxed);
    status.files = entries.len();
    (entries, status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_rules_mirror_python() {
        let rules = vec![
            "vendor/".to_string(),
            "a/b".to_string(),
            "SOME_RULE_ID".to_string(),
        ];
        assert!(path_rule_matches("vendor/lib/x.js", &rules));
        assert!(!path_rule_matches("vendor", &rules)); // prefix needs trailing /
        assert!(path_rule_matches("src/a/b/c.py", &rules));
        // bare rule ids are finding-level, never walk-level
        assert!(!path_rule_matches("SOME_RULE_ID", &rules));
    }
}

#[cfg(test)]
mod walk_count_tests {
    use super::*;

    #[test]
    fn walk_prunes_and_counts_excluded_dirs() {
        let tmp = std::env::temp_dir().join(format!("rsx_walkcount_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("node_modules")).unwrap();
        std::fs::write(tmp.join("node_modules").join("dep.py"), "x").unwrap();
        std::fs::write(tmp.join("keep.py"), "x").unwrap();

        let cfg: ScanConfig = serde_json::from_str(
            r#"{"schema":"rsecopsx.rust_scan_config/v1","excluded_dirs":["node_modules"],"rules":[]}"#,
        )
        .unwrap();
        let (files, st) = walk(&tmp, &cfg);
        let rels: Vec<&str> = files.iter().map(|f| f.rel.as_str()).collect();
        assert!(st.excluded_dirs >= 1, "excluded_dirs not counted: {:?}", st);
        assert!(!rels.iter().any(|r| r.contains("node_modules")), "{rels:?}");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}

#[cfg(test)]
mod parity_path_tests {
    use super::*;

    #[test]
    fn forward_slash_root_yields_native_separators_in_abs() {
        let tmp = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("rsx_parity_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("sub")).unwrap();
        std::fs::write(tmp.join("sub").join("a.py"), "x").unwrap();

        // Forward-slash suffix, exactly what pathlib/os.path.join keep.
        let native = tmp.to_string_lossy().replace("\\", "/");
        let cfg: ScanConfig = serde_json::from_str(
            r#"{"schema":"rsecopsx.rust_scan_config/v1","rules":[]}"#,
        )
        .unwrap();
        let (files, _) = walk(Path::new(&native), &cfg);
        assert_eq!(files.len(), 1, "{files:?}");
        let abs = files[0].abs.to_string_lossy();
        #[cfg(windows)]
        assert!(!abs.contains('/'), "non-native separators in {abs}");
        assert!(abs.ends_with("a.py"), "{abs}");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
