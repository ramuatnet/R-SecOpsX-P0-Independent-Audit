"""
core/mapper.py  v5
Full compliance mapping: OWASP, MITRE, CWE, PCI DSS, NIST 800-53,
ISO 27001 Annex A, SOC 2.

CHANGES (v4 → v5):
  ADD — ssrf mapping
  ADD — insecure_deserialization mapping
"""
from __future__ import annotations

VULN_MAPPING: dict[str, dict] = {

    "sql_injection": {
        "title":"SQL Injection","owasp":"A03:2021 - Injection","owasp_id":"A03",
        "mitre":"T1190","mitre_desc":"Exploit Public-Facing Application",
        "cwe":"CWE-89","cwe_desc":"Improper Neutralization of Special Elements in SQL Command",
        "pci_dss":"Req 6.2.4 - Prevent injection attacks",
        "nist":"SI-10 Information Input Validation",
        "iso27001":"A.14.2.5 Secure System Engineering Principles",
        "soc2":"CC6.1 Logical and Physical Access Controls",
        "severity":"Critical","priority":"P1","exploitability":"High",
        "business_impact":"Complete database compromise, data exfiltration, authentication bypass.",
        "remediation":["Use parameterized queries / prepared statements exclusively.",
                        "Apply an ORM with query parameter binding.",
                        "Validate and sanitize all user-supplied input server-side.",
                        "Implement a WAF rule to detect common SQL injection patterns.",
                        "Apply principle of least privilege on database accounts."],
    },

    "command_injection": {
        "title":"Command Injection","owasp":"A03:2021 - Injection","owasp_id":"A03",
        "mitre":"T1059","mitre_desc":"Command and Scripting Interpreter",
        "cwe":"CWE-78","cwe_desc":"Improper Neutralization of Special Elements in OS Command",
        "pci_dss":"Req 6.2.4 - Prevent injection attacks",
        "nist":"SI-10 Information Input Validation",
        "iso27001":"A.14.2.5 Secure System Engineering Principles",
        "soc2":"CC6.6 Logical Access Security Measures",
        "severity":"Critical","priority":"P1","exploitability":"High",
        "business_impact":"Full server compromise. Remote code execution with application privileges, enabling data theft, ransomware deployment, and lateral movement to internal network segments.",
        "remediation":["Never pass user input directly to shell commands.",
                        "Use subprocess with list arguments and shell=False.",
                        "Apply allow-list validation for any OS-level parameters.",
                        "Run application processes with minimal OS privileges (least privilege).",
                        "Consider sandboxing execution environments."],
    },

    "path_traversal": {
        "title":"Path Traversal","owasp":"A01:2021 - Broken Access Control","owasp_id":"A01",
        "mitre":"T1083","mitre_desc":"File and Directory Discovery",
        "cwe":"CWE-22","cwe_desc":"Improper Limitation of Pathname to Restricted Directory",
        "pci_dss":"Req 6.2.1 - Protect all system components",
        "nist":"AC-3 Access Enforcement",
        "iso27001":"A.9.4.1 Information Access Restriction",
        "soc2":"CC6.1 Logical and Physical Access Controls",
        "severity":"High","priority":"P2","exploitability":"Medium",
        "business_impact":"Unauthorized file read access. Disclosure of configuration files, private keys, source code, and credential stores. May chain into full compromise via exposed secrets.",
        "remediation":["Canonicalize file paths using os.path.realpath() before use.",
                        "Validate that resolved paths reside within an allowed base directory.",
                        "Avoid user-controlled input in file system paths entirely.",
                        "Implement strict access controls on sensitive directories."],
    },

    "xss": {
        "title":"Cross-Site Scripting (XSS)","owasp":"A03:2021 - Injection","owasp_id":"A03",
        "mitre":"T1189","mitre_desc":"Drive-by Compromise",
        "cwe":"CWE-79","cwe_desc":"Improper Neutralization of Input During Web Page Generation",
        "pci_dss":"Req 6.2.4 - Prevent XSS attacks",
        "nist":"SI-10 Information Input Validation",
        "iso27001":"A.14.2.5 Secure System Engineering Principles",
        "soc2":"CC6.7 Transmission of Confidential Information",
        "severity":"High","priority":"P2","exploitability":"Medium",
        "business_impact":"Session hijacking, credential theft, defacement, malware distribution.",
        "remediation":["Use output encoding for all user-controlled data in HTML context.",
                        "Implement a strict Content Security Policy (CSP) header.",
                        "Use templating engines with auto-escaping enabled.",
                        "Validate and reject input containing script tags server-side."],
    },

    "ssrf": {
        "title":"Server-Side Request Forgery (SSRF)",
        "owasp":"A10:2021 - Server-Side Request Forgery","owasp_id":"A10",
        "mitre":"T1190","mitre_desc":"Exploit Public-Facing Application",
        "cwe":"CWE-918","cwe_desc":"Server-Side Request Forgery (SSRF)",
        "pci_dss":"Req 6.2.4 - Prevent SSRF attacks",
        "nist":"SC-7 Boundary Protection",
        "iso27001":"A.13.1.3 Segregation in Networks",
        "soc2":"CC6.6 Logical Access Security Measures",
        "severity":"High","priority":"P2","exploitability":"High",
        "business_impact":"Internal service access, metadata exposure (AWS IMDS), SSRF pivot to RCE, lateral movement.",
        "remediation":["Validate all outbound URLs against a server-side allow-list of trusted hosts.",
                        "Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x).",
                        "Use a dedicated HTTP proxy that enforces egress filtering.",
                        "Disable unnecessary URL schemes (file://, gopher://, dict://).",
                        "Never forward raw user-supplied URLs to backend HTTP clients."],
    },

    "insecure_deserialization": {
        "title":"Insecure Deserialization",
        "owasp":"A08:2021 - Software and Data Integrity Failures","owasp_id":"A08",
        "mitre":"T1059","mitre_desc":"Command and Scripting Interpreter",
        "cwe":"CWE-502","cwe_desc":"Deserialization of Untrusted Data",
        "pci_dss":"Req 6.2.4 - Prevent deserialization attacks",
        "nist":"SI-10 Information Input Validation",
        "iso27001":"A.14.2.5 Secure System Engineering Principles",
        "soc2":"CC6.6 Logical Access Security Measures",
        "severity":"Critical","priority":"P1","exploitability":"High",
        "business_impact":"Arbitrary code execution from malicious serialized payloads. pickle.loads() and yaml.load() are direct RCE vectors with no sandboxing.",
        "remediation":["Never deserialize data from untrusted sources with pickle, marshal, or yaml.load.",
                        "Use yaml.safe_load() instead of yaml.load().",
                        "Use JSON (json.loads) for data interchange — it does not execute code.",
                        "For Java, use allow-listing with ObjectInputFilter or switch to Jackson with polymorphic type disabled.",
                        "Sign and verify serialized payloads before deserialization."],
    },

    "hardcoded_secret": {
        "title":"Hardcoded Secret / Credential",
        "owasp":"A07:2021 - Identification and Authentication Failures","owasp_id":"A07",
        "mitre":"T1552","mitre_desc":"Unsecured Credentials",
        "cwe":"CWE-798","cwe_desc":"Use of Hard-coded Credentials",
        "pci_dss":"Req 8.3.2 - Strong cryptography for credential management",
        "nist":"IA-5 Authenticator Management",
        "iso27001":"A.9.4.3 Password Management System",
        "soc2":"CC6.1 Logical Access Controls",
        "severity":"Critical","priority":"P1","exploitability":"High",
        "business_impact":"Unauthorized service access, data breach, and regulatory violation. Credentials in VCS history persist even after removal from HEAD. Rotation is mandatory and git history must be purged.",
        "remediation":["Remove all hardcoded credentials immediately.",
                        "Store secrets in environment variables or a secrets manager (Vault, AWS Secrets Manager).",
                        "Rotate any exposed credentials immediately.",
                        "Scan git history (truffleHog, gitleaks) and revoke previously committed secrets.",
                        "Add pre-commit hooks (detect-secrets) to prevent future leakage."],
    },

    "weak_crypto": {
        "title":"Weak Cryptography",
        "owasp":"A02:2021 - Cryptographic Failures","owasp_id":"A02",
        "mitre":"T1600","mitre_desc":"Weaken Encryption",
        "cwe":"CWE-327","cwe_desc":"Use of a Broken or Risky Cryptographic Algorithm",
        "pci_dss":"Req 6.2.4 - Prevent use of broken cryptographic algorithms",
        "nist":"SC-13 Cryptographic Protection",
        "iso27001":"A.10.1.1 Policy on the Use of Cryptographic Controls",
        "soc2":"CC6.7 Transmission of Confidential Information",
        "severity":"High","priority":"P2","exploitability":"Medium",
        "business_impact":"Cryptographic bypass enabling password cracking, data integrity violation, and authentication compromise. PCI DSS Req 6.2.4 and NIST SP 800-131A violation.",
        "remediation":["Replace MD5/SHA-1 with SHA-256 or SHA-3 for general hashing.",
                        "Use bcrypt, argon2, or PBKDF2 for password hashing (never MD5/SHA-1).",
                        "Use AES-256-GCM for symmetric encryption.",
                        "Use secrets module instead of random for security-sensitive randomness."],
    },

    "open_redirect": {
        "title":"Open Redirect",
        "owasp":"A01:2021 - Broken Access Control","owasp_id":"A01",
        "mitre":"T1566","mitre_desc":"Phishing",
        "cwe":"CWE-601","cwe_desc":"URL Redirection to Untrusted Site",
        "pci_dss":"Req 6.2.4 - Prevent redirect attacks",
        "nist":"SC-23 Session Authenticity",
        "iso27001":"A.14.2.5 Secure System Engineering Principles",
        "soc2":"CC6.6 Logical Access Security",
        "severity":"Medium","priority":"P3","exploitability":"Medium",
        "business_impact":"Phishing attacks, credential harvesting, brand damage.",
        "remediation":["Validate redirect URLs against an allow-list of trusted domains.",
                        "Use relative URLs for internal redirects.",
                        "Never trust user-supplied next/redirect URL parameters without validation."],
    },

    "auth_bypass": {
        "title":"Authentication / Authorization Bypass",
        "owasp":"A01:2021 - Broken Access Control","owasp_id":"A01",
        "mitre":"T1078","mitre_desc":"Valid Accounts",
        "cwe":"CWE-862","cwe_desc":"Missing Authorization",
        "pci_dss":"Req 7.1 - Limit access to system components",
        "nist":"AC-3 Access Enforcement",
        "iso27001":"A.9.4.1 Information Access Restriction",
        "soc2":"CC6.3 Access to Information Assets",
        "severity":"High","priority":"P2","exploitability":"High",
        "business_impact":"Privilege escalation, unauthorized data access, regulatory violation.",
        "remediation":["Implement server-side authorization checks on every protected endpoint.",
                        "Use role-based access control (RBAC).",
                        "Never rely on client-supplied parameters for privilege determination."],
    },

    "code_injection": {
        "title":"Code Injection (eval/exec)",
        "owasp":"A03:2021 - Injection","owasp_id":"A03",
        "mitre":"T1059","mitre_desc":"Command and Scripting Interpreter",
        "cwe":"CWE-94","cwe_desc":"Improper Control of Generation of Code",
        "pci_dss":"Req 6.2.4 - Prevent injection attacks",
        "nist":"SI-10 Information Input Validation",
        "iso27001":"A.14.2.5 Secure System Engineering Principles",
        "soc2":"CC6.6 Logical Access Security Measures",
        "severity":"Critical","priority":"P1","exploitability":"High",
        "business_impact":"Arbitrary code execution, full system compromise.",
        "remediation":["Never use eval() or exec() on user-controlled input.",
                        "Use ast.literal_eval() for safe data parsing.",
                        "Refactor to use safe alternatives for any dynamic evaluation."],
    },

    "debug_exposure": {
        "title":"Debug / Sensitive Information Exposure",
        "owasp":"A05:2021 - Security Misconfiguration","owasp_id":"A05",
        "mitre":"T1082","mitre_desc":"System Information Discovery",
        "cwe":"CWE-215","cwe_desc":"Insertion of Sensitive Information Into Debugging Code",
        "pci_dss":"Req 6.2.4 - Secure development",
        "nist":"SI-12 Information Management and Retention",
        "iso27001":"A.12.6.1 Management of Technical Vulnerabilities",
        "soc2":"CC7.2 Monitoring of Security Events",
        "severity":"Medium","priority":"P3","exploitability":"Medium",
        "business_impact":"System architecture exposure, credential leakage via debug endpoints.",
        "remediation":["Disable debug mode in all non-development environments.",
                        "Use environment-specific configuration (DEBUG=False in production).",
                        "Ensure stack traces are not returned to end users."],
    },

    "sensitive_logging": {
        "title":"Sensitive Data in Logs",
        "owasp":"A09:2021 - Security Logging and Monitoring Failures","owasp_id":"A09",
        "mitre":"T1005","mitre_desc":"Data from Local System",
        "cwe":"CWE-532","cwe_desc":"Insertion of Sensitive Information into Log File",
        "pci_dss":"Req 10.3 - Protect audit trails",
        "nist":"AU-9 Protection of Audit Information",
        "iso27001":"A.12.4.1 Event Logging",
        "soc2":"CC7.2 Monitoring of Security Events",
        "severity":"Medium","priority":"P3","exploitability":"Low",
        "business_impact":"Credential exposure via log aggregation systems, compliance violation.",
        "remediation":["Scrub or mask sensitive fields before logging.",
                        "Implement structured logging with explicit field allow-lists."],
    },

    "insecure_dependency": {
        "title":"Insecure / Vulnerable Dependency",
        "owasp":"A06:2021 - Vulnerable and Outdated Components","owasp_id":"A06",
        "mitre":"T1195","mitre_desc":"Supply Chain Compromise",
        "cwe":"CWE-1035","cwe_desc":"Using Components with Known Vulnerabilities",
        "pci_dss":"Req 6.3.3 - All software protected from known vulnerabilities",
        "nist":"SA-22 Unsupported System Components",
        "iso27001":"A.12.6.1 Management of Technical Vulnerabilities",
        "soc2":"CC7.1 Vulnerability Management",
        "severity":"High","priority":"P2","exploitability":"Medium",
        "business_impact":"Supply chain attack, known exploits against vulnerable library versions.",
        "remediation":["Upgrade all dependencies to latest stable patched versions.",
                        "Integrate automated SCA scanning in CI/CD (Snyk, Dependabot).",
                        "Maintain a SBOM for all third-party components."],
    },
}


def get_mapping(vuln_type: str) -> dict:
    return VULN_MAPPING.get(vuln_type, {})


def get_owasp_summary(findings: list) -> dict:
    owasp_map: dict = {}
    for f in findings:
        cat = f.get("owasp_id", "Unknown")
        owasp_map.setdefault(cat, {"category": f.get("owasp", cat), "count": 0, "findings": []})
        owasp_map[cat]["count"] += 1
        owasp_map[cat]["findings"].append(f.get("title", ""))
    return owasp_map


def get_mitre_summary(findings: list) -> list:
    seen: set = set()
    techniques = []
    for f in findings:
        tid = f.get("mitre", "")
        if tid and tid not in seen:
            seen.add(tid)
            techniques.append({"id": tid, "description": f.get("mitre_desc", "")})
    return techniques
