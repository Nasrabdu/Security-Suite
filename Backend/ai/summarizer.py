"""
Scan result summarizer (thin wrapper around GeminiClient).
"""

from typing import Any, Dict, List, Optional
from .gemini_client import get_gemini_client, _extract_ports_from_scan


def summarize_scan_results(scan_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Quick AI summary of scan data using Gemini (or fallback)."""
    client = get_gemini_client()
    if client.is_available():
        result = client.summarize_scan(scan_data)
        if result:
            return result
    # Fallback
    ports = _extract_ports_from_scan(scan_data)
    target = (scan_data.get('scan_metadata') or {}).get('target', scan_data.get('target', 'unknown'))
    return {
        'risk_level': 'info',
        'risk_score': 10,
        'summary': f'Scan of {target} completed. Found {len(ports)} open port(s). Set GEMINI_API_KEY for AI analysis.',
        'key_findings': [f'{len(ports)} open port(s) discovered'],
        'recommendations': ['Review all open ports', 'Update all services', 'Configure firewall']
    }


def classify_all_vulnerabilities(scan_data: Dict[str, Any]) -> List[Dict]:
    """Extract all vulnerability records from scan data."""
    vulns = []
    results = scan_data.get('results', {})
    if isinstance(results, dict):
        for key, val in results.items():
            if isinstance(val, dict):
                vulns.extend(val.get('vulnerabilities', []))
    vulns.extend(scan_data.get('vulnerabilities', []))
    return vulns
