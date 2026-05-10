#!/usr/bin/env python3
"""
theHarvester Integration Script for Security Suite (Pentest Platform)
- Performs OSINT reconnaissance against a domain
- Collects emails, subdomains, and IP addresses from public sources
"""

from __future__ import annotations

import subprocess
from typing import Any, Dict, List


def run_harvester(domain: str) -> Dict[str, Any]:
    """Run theHarvester against domain and return structured OSINT results."""
    command = [
        'theHarvester',
        '-d', domain,
        '-b', 'bing,duckduckgo,crtsh',
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = (result.stdout or '') + (result.stderr or '')
        emails: List[str] = []
        subdomains: List[str] = []
        ips: List[str] = []

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if '@' in line:
                emails.append(line)
            else:
                subdomains.append(line)

        return {
            'emails': emails,
            'subdomains': subdomains,
            'ips': ips,
            'raw_output': output[:5000],
        }

    except subprocess.TimeoutExpired:
        return {'emails': [], 'subdomains': [], 'ips': [], 'raw_output': 'Scan exceeded timeout (120s)'}
    except Exception as e:
        return {'emails': [], 'subdomains': [], 'ips': [], 'raw_output': str(e)}
