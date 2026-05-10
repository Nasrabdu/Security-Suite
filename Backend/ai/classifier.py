"""
AI-Powered Vulnerability Classification
Classify vulnerabilities by CVE, OWASP Top 10, and severity using Gemini.
"""

from typing import Dict, Any, Optional, List
from .gemini_client import get_gemini_client
from .prompts import (
    SECURITY_EXPERT_SYSTEM,
    CLASSIFY_VULNERABILITY_PROMPT,
    MAP_TO_OWASP_PROMPT,
    CVE_LOOKUP_PROMPT,
    format_vulnerability_for_ai,
)


def classify_vulnerability(
    port: int,
    service: str,
    version: str = "",
    description: str = "",
) -> Optional[Dict[str, Any]]:
    """
    Classify a vulnerability using Gemini AI.
    Falls back to rule-based classification when Gemini is unavailable.
    """
    client = get_gemini_client()

    if not client.is_available():
        return fallback_classification(port, service, version)

    vuln_data = format_vulnerability_for_ai(port, service, version, description)

    prompt = CLASSIFY_VULNERABILITY_PROMPT.format(
        port=vuln_data['port'],
        service=vuln_data['service'],
        version=vuln_data['version'],
        description=vuln_data['description'],
    )

    try:
        classification = client.generate_json(
            prompt=prompt,
            system_prompt=SECURITY_EXPERT_SYSTEM,
            temperature=0.3,
        )
        if classification:
            print(f"✓ Classified vulnerability for {service} on port {port}")
            return classification
        return fallback_classification(port, service, version)
    except Exception as e:
        print(f"Error classifying vulnerability: {e}")
        return fallback_classification(port, service, version)


def map_to_owasp(vulnerability_description: str) -> Optional[Dict[str, Any]]:
    """Map a vulnerability description to OWASP Top 10 2021 using Gemini."""
    client = get_gemini_client()

    if not client.is_available():
        return None

    prompt = MAP_TO_OWASP_PROMPT.format(
        vulnerability_description=vulnerability_description
    )

    try:
        mapping = client.generate_json(
            prompt=prompt,
            system_prompt=SECURITY_EXPERT_SYSTEM,
            temperature=0.3,
        )
        if mapping:
            print(f"✓ Mapped to OWASP: {mapping.get('owasp_category')}")
            return mapping
        return None
    except Exception as e:
        print(f"Error mapping to OWASP: {e}")
        return None


def lookup_cves(service: str, version: str, additional_info: str = "") -> Optional[List[Dict[str, Any]]]:
    """Look up potential CVEs for a service/version using Gemini."""
    client = get_gemini_client()

    if not client.is_available():
        return None

    prompt = CVE_LOOKUP_PROMPT.format(
        service=service,
        version=version,
        additional_info=additional_info,
    )

    try:
        result = client.generate_json(
            prompt=prompt,
            system_prompt=SECURITY_EXPERT_SYSTEM,
            temperature=0.4,
        )
        if result and 'cves' in result:
            cves = result['cves']
            print(f"✓ Found {len(cves)} potential CVEs for {service} {version}")
            return cves
        return []
    except Exception as e:
        print(f"Error looking up CVEs: {e}")
        return []


def fallback_classification(port: int, service: str, version: str) -> Dict[str, Any]:
    """Rule-based classification used when Gemini is unavailable."""
    high_risk_services = {
        21:   ('ftp',     'FTP service allows unencrypted file transfer'),
        23:   ('telnet',  'Telnet transmits credentials in plaintext'),
        80:   ('http',    'HTTP service without encryption'),
        139:  ('netbios', 'NetBIOS service may expose sensitive information'),
        445:  ('smb',     'SMB service may be vulnerable to exploits'),
        3389: ('rdp',     'RDP service may allow remote access'),
    }

    severity    = 'info'
    title       = f"Open {service} service on port {port}"
    description = f"Service {service} is accessible on port {port}"

    if port in high_risk_services:
        expected_service, risk_desc = high_risk_services[port]
        if service.lower() == expected_service or service == 'unknown':
            severity    = 'medium'
            description = risk_desc

    if version and 'old' in version.lower():
        severity = 'high'

    return {
        'title':          title,
        'severity':       severity,
        'cvss_score':     5.0 if severity == 'medium' else 3.0,
        'owasp_category': 'A05:2021',
        'owasp_name':     'Security Misconfiguration',
        'cve_ids':        [],
        'description':    description,
        'impact':         'Service exposure may lead to unauthorized access',
        'remediation':    f'Review necessity of {service} service and apply security hardening',
        'references':     [],
    }


def classify_all_vulnerabilities(scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Classify all open-port vulnerabilities from scan results."""
    vulnerabilities = []

    if 'results' not in scan_results:
        return vulnerabilities

    for scan_type, data in scan_results['results'].items():
        if 'ports' not in data:
            continue
        for port_info in data['ports']:
            if port_info.get('state') != 'open':
                continue

            port    = port_info.get('port')
            service = port_info.get('service', 'unknown')
            version = port_info.get('version', '')

            classification = classify_vulnerability(
                port=port,
                service=service,
                version=version,
                description=f"Open {service} service detected",
            )

            if classification:
                classification['port']    = port
                classification['service'] = service
                classification['version'] = version
                vulnerabilities.append(classification)

    return vulnerabilities
