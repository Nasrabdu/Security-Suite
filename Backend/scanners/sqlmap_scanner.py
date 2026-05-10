#!/usr/bin/env python3
"""
SQLMap Integration Script for Security Suite (Pentest Platform)
- Runs sqlmap against a target URL with configurable depth level
- Detects SQL injection findings and maps them to OWASP Top 10
"""

from __future__ import annotations

import subprocess
from typing import Any, Dict, List


def run_sqlmap(target_url: str, level: int = 1) -> Dict[str, Any]:
    """Run sqlmap against target_url and return structured findings."""
    command = [
        'sqlmap',
        '-u', target_url,
        '--batch',
        '--level', str(level),
        '--forms',
        '--crawl=2',
        '--timeout=30',
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = (result.stdout or '') + (result.stderr or '')
        findings: List[Dict[str, Any]] = []

        if 'Parameter:' in output or 'injectable' in output:
            findings.append({
                'title': 'SQL Injection',
                'severity': 'critical',
                'owasp': 'A03:2021 - Injection',
                'remediation': 'Use parameterized queries',
            })

        return {
            'findings': findings,
            'raw_output': output[:5000],
        }

    except subprocess.TimeoutExpired:
        return {'findings': [], 'raw_output': 'Scan exceeded timeout (120s)'}
    except Exception as e:
        return {'findings': [], 'raw_output': str(e)}
