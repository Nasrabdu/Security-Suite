OWASP_TOP_10 = {
    "A01:2021": {
        "owasp_id": "A01:2021",
        "owasp_name": "Broken Access Control",
        "description": (
            "Restrictions on what authenticated users are allowed to do are often not properly enforced. "
            "Attackers can exploit these flaws to access unauthorized functionality or data."
        ),
        "link": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    },
    "A02:2021": {
        "owasp_id": "A02:2021",
        "owasp_name": "Cryptographic Failures",
        "description": (
            "Failures related to cryptography which often lead to exposure of sensitive data. "
            "Includes weak algorithms, missing encryption, and improper key management."
        ),
        "link": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    },
    "A03:2021": {
        "owasp_id": "A03:2021",
        "owasp_name": "Injection",
        "description": (
            "User-supplied data is not validated, filtered, or sanitized. "
            "Includes SQL, NoSQL, OS, and LDAP injection, XSS, and template injection."
        ),
        "link": "https://owasp.org/Top10/A03_2021-Injection/",
    },
    "A04:2021": {
        "owasp_id": "A04:2021",
        "owasp_name": "Insecure Design",
        "description": (
            "Missing or ineffective control design representing weaknesses in business logic "
            "and architecture that cannot be fixed by correct implementation alone."
        ),
        "link": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    },
    "A05:2021": {
        "owasp_id": "A05:2021",
        "owasp_name": "Security Misconfiguration",
        "description": (
            "Missing appropriate security hardening, insecure default configurations, "
            "unnecessary features enabled, or verbose error messages exposing sensitive information."
        ),
        "link": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },
    "A06:2021": {
        "owasp_id": "A06:2021",
        "owasp_name": "Vulnerable and Outdated Components",
        "description": (
            "Using components with known vulnerabilities such as outdated libraries, frameworks, "
            "or software that may undermine application defenses."
        ),
        "link": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    },
    "A07:2021": {
        "owasp_id": "A07:2021",
        "owasp_name": "Identification and Authentication Failures",
        "description": (
            "Weaknesses in authentication and session management that allow attackers to compromise "
            "passwords, keys, or session tokens to assume user identities."
        ),
        "link": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    },
    "A08:2021": {
        "owasp_id": "A08:2021",
        "owasp_name": "Software and Data Integrity Failures",
        "description": (
            "Code and infrastructure that does not protect against integrity violations, including "
            "insecure deserialization, unsigned updates, and untrusted CI/CD pipelines."
        ),
        "link": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    },
    "A09:2021": {
        "owasp_id": "A09:2021",
        "owasp_name": "Security Logging and Monitoring Failures",
        "description": (
            "Insufficient logging, detection, monitoring, and active response allowing attackers "
            "to persist, pivot, and tamper with or extract data undetected."
        ),
        "link": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    },
    "A10:2021": {
        "owasp_id": "A10:2021",
        "owasp_name": "Server-Side Request Forgery",
        "description": (
            "SSRF flaws occur when a web application fetches a remote resource without validating "
            "the user-supplied URL, allowing attackers to coerce requests to internal services."
        ),
        "link": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    },
}

# Maps keyword fragments to OWASP category IDs
_KEYWORD_MAP: list[tuple[list[str], str]] = [
    (["sql", "sqli", "nosql", "ldap inject", "command inject", "code inject", "xss",
      "cross-site script", "template inject", "ssti", "injection"], "A03:2021"),
    (["broken access", "access control", "idor", "privilege escal", "path traversal",
      "directory traversal", "unauthorized", "lfi", "rfi"], "A01:2021"),
    (["crypto", "encryption", "tls", "ssl", "weak cipher", "plaintext", "clear text",
      "sensitive data", "certificate", "hash", "md5", "sha1"], "A02:2021"),
    (["insecure design", "business logic", "race condition", "logic flaw"], "A04:2021"),
    (["misconfigur", "default credential", "default password", "exposed admin",
      "debug enabled", "unnecessary service", "open port", "information disclosure",
      "banner", "error message", "stack trace"], "A05:2021"),
    (["outdated", "vulnerable component", "cve", "known vulnerability", "unpatched",
      "deprecated", "end of life", "eol"], "A06:2021"),
    (["auth failure", "authentication", "brute force", "weak password", "session fixation",
      "session hijack", "credential", "mfa", "2fa", "account lockout", "jwt"], "A07:2021"),
    (["deserialization", "integrity", "supply chain", "unsigned", "untrusted update",
      "ci/cd", "pipeline"], "A08:2021"),
    (["logging", "monitoring", "audit", "log injection", "no log", "missing log",
      "alerting", "detection"], "A09:2021"),
    (["ssrf", "server-side request", "server side request", "internal request",
      "open redirect"], "A10:2021"),
]

_DEFAULT_ID = "A05:2021"


def map_to_owasp(finding_type: str) -> dict:
    normalized = finding_type.lower().strip()

    for keywords, owasp_id in _KEYWORD_MAP:
        if any(kw in normalized for kw in keywords):
            return OWASP_TOP_10[owasp_id]

    return OWASP_TOP_10[_DEFAULT_ID]


def get_all_owasp() -> list[dict]:
    return list(OWASP_TOP_10.values())
