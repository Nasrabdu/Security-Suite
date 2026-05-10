#!/usr/bin/env python3
"""
Nikto Integration Script for Security Suite (Pentest Platform)
- Runs a web server scan against a target
- Parses OSVDB/CVE findings and maps them to OWASP Top 10
"""

from __future__ import annotations

import subprocess
from typing import Any, Dict, List


def run_nikto(target: str) -> Dict[str, Any]:
    """Run nikto against target and return structured findings."""
    if not target.startswith('http'):
        target = 'http://' + target

    command = ['nikto', '-h', target, '-nointeractive', '-Format', 'txt']

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180,
        )
        output = (result.stdout or '') + (result.stderr or '')
        findings: List[Dict[str, Any]] = []

        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith('+') and ('OSVDB' in stripped or 'CVE' in stripped):
                description = stripped.lstrip('+ ').strip()
                title = description.split(':')[0].strip()
                findings.append({
                    'title': title,
                    'severity': 'medium',
                    'description': description,
                    'owasp_category': 'A05:2021 - Security Misconfiguration',
                })

        return {
            'findings': findings,
            'raw_output': output[:5000],
        }

    except subprocess.TimeoutExpired:
        return {'findings': [], 'raw_output': 'Scan exceeded timeout (180s)'}
    except Exception as e:
        return {'findings': [], 'raw_output': str(e)}
