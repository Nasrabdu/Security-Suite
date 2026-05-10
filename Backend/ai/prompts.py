"""
AI Prompts Library
Prompt templates for various AI tasks
"""

# System prompts
SECURITY_EXPERT_SYSTEM = """You are a professional cybersecurity expert and penetration tester with deep knowledge of:
- Network security and vulnerability assessment
- OWASP Top 10 vulnerabilities
- CVE database and vulnerability classification
- CVSS scoring methodology
- Security best practices and remediation strategies

Provide accurate, actionable security analysis."""

# Scan summarization prompts
SUMMARIZE_SCAN_PROMPT = """Analyze this Nmap scan result and provide a comprehensive security assessment.

Scan Data:
{scan_data}

Provide your analysis in the following JSON format:
{{
  "executive_summary": "2-3 sentence high-level summary",
  "key_findings": ["finding 1", "finding 2", "finding 3"],
  "risk_level": "critical|high|medium|low|info",
  "open_ports_summary": "summary of open ports and services",
  "security_concerns": ["concern 1", "concern 2"],
  "recommendations": ["recommendation 1", "recommendation 2"]
}}

Focus on security implications and actionable insights."""

# Vulnerability classification prompts
CLASSIFY_VULNERABILITY_PROMPT = """Classify this security vulnerability and provide detailed analysis.

Vulnerability Information:
Port: {port}
Service: {service}
Version: {version}
Description: {description}

Provide classification in JSON format:
{{
  "title": "Clear vulnerability title",
  "severity": "critical|high|medium|low|info",
  "cvss_score": 7.5,
  "owasp_category": "A03:2021",
  "owasp_name": "Injection",
  "cve_ids": ["CVE-2021-12345"],
  "description": "Detailed description",
  "impact": "What could an attacker do",
  "remediation": "How to fix this",
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-12345"]
}}

Be specific and accurate. If no CVE exists, use empty array."""

# OWASP mapping prompt
MAP_TO_OWASP_PROMPT = """Map this vulnerability to the OWASP Top 10 2021 framework.

Vulnerability: {vulnerability_description}

OWASP Top 10 2021:
- A01:2021 - Broken Access Control
- A02:2021 - Cryptographic Failures
- A03:2021 - Injection
- A04:2021 - Insecure Design
- A05:2021 - Security Misconfiguration
- A06:2021 - Vulnerable and Outdated Components
- A07:2021 - Identification and Authentication Failures
- A08:2021 - Software and Data Integrity Failures
- A09:2021 - Security Logging and Monitoring Failures
- A10:2021 - Server-Side Request Forgery (SSRF)

Return JSON:
{{
  "owasp_category": "A03:2021",
  "owasp_name": "Injection",
  "confidence": 0.95,
  "reasoning": "Why this mapping is appropriate"
}}"""

# CVE lookup prompt
CVE_LOOKUP_PROMPT = """Based on this service and version information, identify potential CVE vulnerabilities.

Service: {service}
Version: {version}
Additional Info: {additional_info}

Return JSON array of potential CVEs:
{{
  "cves": [
    {{
      "cve_id": "CVE-2021-12345",
      "cvss_score": 9.8,
      "severity": "critical",
      "description": "Brief description",
      "likelihood": "high|medium|low"
    }}
  ]
}}

Only include CVEs that are likely to apply. If uncertain, indicate lower likelihood."""

# Remediation advice prompt
REMEDIATION_PROMPT = """Provide detailed remediation steps for this vulnerability.

Vulnerability: {vulnerability_title}
Severity: {severity}
Affected Service: {service}
Current Version: {version}

Provide remediation in JSON format:
{{
  "immediate_actions": ["action 1", "action 2"],
  "long_term_fixes": ["fix 1", "fix 2"],
  "upgrade_to": "recommended version",
  "configuration_changes": ["change 1", "change 2"],
  "verification_steps": ["how to verify fix worked"]
}}

Be specific and actionable."""

# Port analysis prompt
ANALYZE_PORTS_PROMPT = """Analyze these open ports from a security perspective.

Open Ports:
{ports_data}

Provide analysis in JSON format:
{{
  "high_risk_ports": [
    {{
      "port": 23,
      "service": "telnet",
      "risk": "Unencrypted protocol, credentials sent in plaintext",
      "recommendation": "Disable telnet, use SSH instead"
    }}
  ],
  "unnecessary_services": ["service 1", "service 2"],
  "security_score": 65,
  "overall_assessment": "Brief assessment"
}}"""


def format_scan_data_for_ai(scan_results: dict) -> str:
    """Format scan results for AI consumption"""
    formatted = []
    
    if 'results' in scan_results:
        for scan_type, data in scan_results['results'].items():
            formatted.append(f"\n{scan_type.upper()} SCAN:")
            if 'ports' in data:
                formatted.append("Open Ports:")
                for port in data['ports']:
                    formatted.append(
                        f"  - Port {port.get('port')}/{port.get('protocol')}: "
                        f"{port.get('service', 'unknown')} ({port.get('state', 'unknown')})"
                    )
    
    return "\n".join(formatted)


def format_vulnerability_for_ai(port: int, service: str, version: str = "", description: str = "") -> dict:
    """Format vulnerability data for AI classification"""
    return {
        "port": port,
        "service": service,
        "version": version or "unknown",
        "description": description or f"Open {service} service on port {port}"
    }
