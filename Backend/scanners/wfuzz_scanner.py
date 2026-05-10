#!/usr/bin/env python3
"""
Wfuzz Integration Script for Security Suite (Pentest Platform)
- Fuzzes a target URL for hidden paths using a wordlist
- Returns discovered paths with their HTTP status codes
"""

from __future__ import annotations

import re
import subprocess
from typing import Any, Dict, List


def run_wfuzz(
    target: str,
    wordlist: str = '/usr/share/wordlists/dirb/common.txt',
) -> Dict[str, Any]:
    """Run wfuzz directory brute-force against target and return found paths."""
    if not target.startswith('http'):
        target = 'http://' + target

    command = [
        'wfuzz',
        '-c',
        '-z', f'file,{wordlist}',
        '--hc', '404',
        f'{target}/FUZZ',
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180,
        )
        output = (result.stdout or '') + (result.stderr or '')
        found_paths: List[Dict[str, Any]] = []

        # wfuzz line format: "000000001:   200   9 L   22 W   226 Ch   "path""
        for line in output.splitlines():
            match = re.search(r':\s+(\d{3})\s+.*?"(.*?)"', line)
            if match:
                status_code = match.group(1)
                if status_code in ('200', '301', '302'):
                    found_paths.append({
                        'path': match.group(2),
                        'status_code': status_code,
                        'severity': 'info',
                    })

        return {
            'found_paths': found_paths,
            'raw_output': output[:5000],
        }

    except subprocess.TimeoutExpired:
        return {'found_paths': [], 'raw_output': 'Scan exceeded timeout (180s)'}
    except Exception as e:
        return {'found_paths': [], 'raw_output': str(e)}
