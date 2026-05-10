"""
AI Report Generator - Gemini-powered
Generates rich structured reports from real scan data only.
"""

import json
from typing import Any, Dict, List, Optional

from .gemini_client import get_gemini_client, _extract_ports_from_scan


def summarize_scan_results(scan_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Generate a quick AI summary of scan results using Gemini."""
    client = get_gemini_client()
    if client.is_available():
        result = client.summarize_scan(scan_data)
        if result:
            return result
    # Fallback: rule-based summary
    return _fallback_summary(scan_data)


def classify_all_vulnerabilities(scan_data: Dict[str, Any]) -> List[Dict]:
    """Extract and classify vulnerabilities from scan data."""
    vulns = []
    results = scan_data.get('results', {})
    if isinstance(results, dict):
        for key, val in results.items():
            if isinstance(val, dict):
                vulns.extend(val.get('vulnerabilities', []))
    # Also top-level vulns
    vulns.extend(scan_data.get('vulnerabilities', []))
    return vulns


def generate_ai_report(scan_data: Dict[str, Any], vulnerabilities: List[Dict] = None) -> Dict[str, Any]:
    """
    Generate a comprehensive AI report from real scan data.
    Falls back to rule-based report if Gemini unavailable.
    """
    vulns = vulnerabilities or classify_all_vulnerabilities(scan_data)
    client = get_gemini_client()

    if client.is_available():
        try:
            report = client.generate_full_report(scan_data, vulns)
            if report:
                report = _validate_report(report, scan_data, vulns)
                report['ai_generated'] = True
                print("✓ Gemini AI report generated successfully")
                return report
        except Exception as e:
            print(f"Gemini report generation failed: {e}")

    # Fallback
    return _generate_fallback_report(scan_data, vulns)


def _fallback_summary(scan_data: Dict) -> Dict:
    ports = _extract_ports_from_scan(scan_data)
    target = (scan_data.get('scan_metadata') or {}).get('target', scan_data.get('target', 'unknown'))
    return {
        'risk_level': 'info',
        'risk_score': 15,
        'summary': f'Scan of {target} completed. Found {len(ports)} open port(s). AI analysis unavailable.',
        'key_findings': [f'{len(ports)} open port(s) discovered'],
        'recommendations': [
            'Review all open ports and disable unnecessary ones',
            'Ensure all services are up-to-date',
            'Configure firewall rules appropriately'
        ]
    }


def _validate_report(report: Dict, scan_data: Dict, vulnerabilities: list) -> Dict:
    ports = _extract_ports_from_scan(scan_data)
    defaults = {
        'executive_summary': 'Security assessment completed.',
        'risk_score': 50,
        'risk_grade': 'C',
        'risk_level': 'medium',
        'threat_narrative': '',
        'severity_distribution': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
        'top_findings': [],
        'recommendations': [],
        'port_risk_data': [],
        'attack_surface_summary': {
            'total_open_ports': len(ports),
            'high_risk_services': 0,
            'outdated_services': 0,
            'encrypted_services': 0,
            'unencrypted_services': 0
        },
        'compliance_notes': [],
        'mitigation_roadmap': [],
    }
    for key, val in defaults.items():
        if key not in report:
            report[key] = val
    return report


def _generate_fallback_report(scan_data: Dict, vulnerabilities: list) -> Dict:
    """Rule-based report when Gemini is unavailable."""
    ports = _extract_ports_from_scan(scan_data)
    target = (scan_data.get('scan_metadata') or {}).get('target', scan_data.get('target', 'the target'))

    sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for v in vulnerabilities:
        s = (v.get('severity') or 'info').lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    risk_score = min(100, (
        sev_counts['critical'] * 25 +
        sev_counts['high'] * 15 +
        sev_counts['medium'] * 8 +
        sev_counts['low'] * 3 +
        sev_counts['info'] * 1
    ))
    if risk_score == 0 and len(ports) > 5:
        risk_score = 20

    if risk_score <= 20:   risk_grade, risk_level = 'A', 'low'
    elif risk_score <= 40: risk_grade, risk_level = 'B', 'low'
    elif risk_score <= 60: risk_grade, risk_level = 'C', 'medium'
    elif risk_score <= 80: risk_grade, risk_level = 'D', 'high'
    else:                  risk_grade, risk_level = 'F', 'critical'

    risky = {'ftp': 70, 'telnet': 90, 'http': 45, 'smb': 75, 'rdp': 80, 'vnc': 80}
    port_risk_data = []
    for p in ports:
        svc = p.get('service', {})
        svc_name = svc.get('name', '') if isinstance(svc, dict) else str(svc or '')
        pr = risky.get(svc_name.lower(), 25)
        port_risk_data.append({
            'port': p.get('port'),
            'service': svc_name or 'unknown',
            'risk_level': 'high' if pr > 60 else 'medium' if pr > 40 else 'low',
            'risk_score': pr,
            'risk_reason': 'Known risky service' if pr > 60 else 'Standard service'
        })

    return {
        'executive_summary': (
            f'Security assessment of {target} identified {len(ports)} open port(s) and '
            f'{len(vulnerabilities)} potential issue(s). '
            f'Overall risk score: {risk_score}/100 (Grade {risk_grade}). '
            f'{"Immediate remediation is recommended." if risk_score > 60 else "Continue monitoring and apply best practices."}'
        ),
        'risk_score': risk_score,
        'risk_grade': risk_grade,
        'risk_level': risk_level,
        'threat_narrative': (
            f'The security assessment of {target} reveals a {risk_level} risk posture. '
            f'A total of {len(vulnerabilities)} security issue(s) were identified across {len(ports)} open service(s). '
            f'This report was generated using rule-based analysis (AI not available — set GEMINI_API_KEY to enable AI analysis).'
        ),
        'severity_distribution': sev_counts,
        'top_findings': [
            {
                'title': v.get('title', 'Unknown Finding'),
                'severity': v.get('severity', 'info'),
                'description': v.get('description', 'No description available'),
                'impact': 'Review and assess impact',
                'affected_component': f"Port {v.get('affected_port', 'N/A')} / {v.get('affected_service', 'Unknown')}",
                'remediation': v.get('remediation', 'Review and remediate')
            }
            for v in vulnerabilities[:10]
        ],
        'recommendations': [
            {'priority': 'high', 'action': 'Review and patch all high/critical severity findings', 'effort': 'medium', 'impact_reduction': 'Significant risk reduction'},
            {'priority': 'medium', 'action': 'Ensure all services run the latest stable versions', 'effort': 'low', 'impact_reduction': 'Reduces exposure to known CVEs'},
            {'priority': 'low', 'action': 'Disable unused open ports and services', 'effort': 'low', 'impact_reduction': 'Reduces attack surface'},
        ],
        'port_risk_data': port_risk_data,
        'attack_surface_summary': {
            'total_open_ports': len(ports),
            'high_risk_services': sum(1 for p in port_risk_data if p['risk_score'] > 60),
            'outdated_services': 0,
            'encrypted_services': sum(1 for p in port_risk_data if p['service'] in ['https', 'ssh', 'imaps', 'smtps']),
            'unencrypted_services': sum(1 for p in port_risk_data if p['service'] in ['http', 'ftp', 'telnet', 'smtp']),
        },
        'compliance_notes': [
            'Ensure PCI DSS compliance by remediating all high-severity findings',
            'Review open ports against your organizational security policy',
        ],
        'mitigation_roadmap': [
            {'phase': 'Immediate (0-7 days)', 'actions': ['Patch critical vulnerabilities', 'Disable unnecessary services']},
            {'phase': 'Short-term (1-4 weeks)', 'actions': ['Update all service versions', 'Configure firewall rules']},
            {'phase': 'Long-term (1-3 months)', 'actions': ['Implement continuous monitoring', 'Schedule regular penetration tests']},
        ],
        'ai_generated': False,
    }
