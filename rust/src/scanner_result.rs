//! Third-party scanner-result detection -- direct ports of
//! file_index._is_scanner_result_json and scanner.sast._is_scanner_result_xml.
//!
//! Detection is by CONTENT (tool signatures in the document), never by
//! filename, so an application config that merely mentions "findings" is
//! still scanned. Both checks read only a bounded header: a 17-64 MB
//! findsecbugs/ZAP export is never loaded into memory.
//!
//! Parity: tests/test_rust_core.py compares these decisions against the
//! Python implementations across the corpus.

use std::fs::File;
use std::io::Read;
use std::path::Path;

fn read_head(path: &Path, cap: usize) -> Option<String> {
    let mut f = File::open(path).ok()?;
    let mut buf = vec![0u8; cap];
    let mut total = 0usize;
    while total < cap {
        match f.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => return None,
        }
    }
    buf.truncate(total);
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Port of file_index._is_scanner_result_json: report envelope markers
/// (`total_findings`/`scan_date` + `tool` + `findings`/`secret-id`) plus
/// the member-shape marker (`rule_id` or `secret-id`).
pub fn is_scanner_result_json(path: &Path) -> bool {
    if !path
        .extension()
        .map_or(false, |e| e.eq_ignore_ascii_case("json"))
    {
        return false;
    }
    let Some(head) = read_head(path, 4096) else {
        return false;
    };
    if !head.contains("\"total_findings\"") && !head.contains("\"scan_date\"") {
        return false;
    }
    if !head.contains("\"tool\"") {
        return false;
    }
    if !head.contains("\"findings\"") && !head.contains("\"secret-id\"") {
        return false;
    }
    head.contains("\"rule_id\"") || head.contains("\"secret-id\"")
}

const SCANNER_XML_ROOTS: [&str; 5] = [
    "BugCollection",
    "FindBugsSummary",
    "OWASPZAPReport",
    "CodeIssueCollection",
    "pmd",
];

/// Port of scanner.sast._is_scanner_result_xml: root element wins over
/// extension/dir names; the sonar web export needs the corroborating
/// `<issues>` + `<component>` siblings.
pub fn is_scanner_result_xml(path: &Path) -> bool {
    if !path
        .extension()
        .map_or(false, |e| e.eq_ignore_ascii_case("xml"))
    {
        return false;
    }
    let Some(head) = read_head(path, 4096) else {
        return false;
    };
    // Python strips ONE declaration (count=1) and lstrips before matching
    // the first tag name.
    let rest = if let Some(idx) = head.find("<?xml") {
        match head[idx..].find("?>") {
            Some(end) => &head[idx + end + 2..],
            None => head.as_str(),
        }
    } else {
        head.as_str()
    };
    let rest = rest.trim_start();
    let Some(after) = rest.strip_prefix('<') else {
        return false;
    };
    let mut name = String::new();
    let mut chars = after.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => name.push(c),
        _ => return false,
    }
    for c in chars {
        if c.is_ascii_alphanumeric() || c == '_' || c == ':' || c == '.' || c == '-' {
            name.push(c);
        } else {
            break;
        }
    }
    if SCANNER_XML_ROOTS.contains(&name.as_str()) {
        return true;
    }
    name == "total"
        && head.contains("<issues>")
        && head.contains("<component>")
}
