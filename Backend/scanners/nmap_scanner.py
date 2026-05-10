#!/usr/bin/env python3
"""
Nmap Integration Script for Security Suite (Pentest Platform)
Optimized for Kali Linux
- Runs one of several curated scan profiles
- Produces JSON output (parsed from Nmap XML)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Dict, List, Optional


class NmapScanner:
    """Nmap scanner with curated scanning profiles and JSON output."""

    # OWASP Top 10 2021 Mapping (best-effort mapping for labeling)
    OWASP_MAPPING = {
        'sql_injection': 'A03:2021 - Injection',
        'xss': 'A03:2021 - Injection',
        'auth_bypass': 'A07:2021 - Identification and Authentication Failures',
        'broken_access': 'A01:2021 - Broken Access Control',
        'crypto_fail': 'A02:2021 - Cryptographic Failures',
        'misconfig': 'A05:2021 - Security Misconfiguration',
        'outdated': 'A06:2021 - Vulnerable and Outdated Components',
        'ssrf': 'A10:2021 - Server-Side Request Forgery (SSRF)',
        'logging': 'A09:2021 - Security Logging and Monitoring Failures',
        'integrity': 'A08:2021 - Software and Data Integrity Failures',
    }

    @staticmethod
    def get_nvd_severity(cvss_score: float) -> str:
        if cvss_score >= 9.0:
            return "CRITICAL"
        if cvss_score >= 7.0:
            return "HIGH"
        if cvss_score >= 4.0:
            return "MEDIUM"
        if cvss_score > 0:
            return "LOW"
        return "INFO"

    def __init__(self, target: str):
        self.raw_target = target
        self.target_host = self._extract_host(target)
        self.scan_results: Dict[str, Any] = {
            "scan_metadata": {
                "target": target,
                "target_host": self.target_host,
                "scan_date": datetime.utcnow().isoformat() + "Z",
                "scanner": "nmap",
                "version": self._get_nmap_version(),
            },
            "results": {},
            "vulnerabilities": [],
            "summary": {},
        }

    def _extract_host(self, url_or_host: str) -> str:
        host = re.sub(r'^https?://', '', url_or_host.strip())
        host = host.split('/')[0]
        host = host.split(':')[0]
        return host

    def _get_nmap_version(self) -> str:
        try:
            result = subprocess.run(['nmap', '--version'], capture_output=True, text=True, timeout=5)
            version_line = (result.stdout or '').split('\n')[0]
            return version_line.replace('Nmap version ', '').strip() or "Unknown"
        except Exception:
            return "Unknown"

    def _downgrade_if_unprivileged(self, command: List[str]) -> List[str]:
        """If not root: replace SYN scan -sS with TCP connect -sT and drop OS detection -O."""
        try:
            if os.geteuid() != 0:
                command = ['-sT' if x == '-sS' else x for x in command]
                command = [x for x in command if x != '-O']
        except AttributeError:
            # os.geteuid not available on Windows; ignore
            pass
        return command

    def _run_nmap_command(self, command: List[str], scan_name: str) -> Dict[str, Any]:
        command = self._downgrade_if_unprivileged(command)
        start_time = datetime.utcnow()

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=600,  # up to 10 min (some scans can be slow)
            )
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()

            if result.returncode != 0:
                return {"status": "failed", "error": (result.stderr or '').strip(), "duration": duration, "command": ' '.join(command)}

            parsed_results = self._parse_nmap_xml(result.stdout or '')
            parsed_results.update({
                "duration": duration,
                "status": "completed",
                "command": ' '.join(command),
                "scan_name": scan_name,
            })
            return parsed_results

        except subprocess.TimeoutExpired:
            return {"status": "timeout", "error": "Scan exceeded timeout", "duration": 600, "command": ' '.join(command)}
        except Exception as e:
            return {"status": "error", "error": str(e), "duration": 0, "command": ' '.join(command)}

    def _parse_nmap_xml(self, xml_output: str) -> Dict[str, Any]:
        try:
            root = ET.fromstring(xml_output)
        except Exception:
            return {"parsed": False, "raw_output": xml_output[:5000]}

        results: Dict[str, Any] = {
            "parsed": True,
            "hosts": [],
            "ports": [],
            "services": [],
            "vulnerabilities": [],
        }

        for host in root.findall('.//host'):
            host_data = self._parse_host(host)
            results["hosts"].append(host_data)
            results["ports"].extend(host_data.get("ports", []))
            results["services"].extend(host_data.get("services", []))
            results["vulnerabilities"].extend(self._extract_vulnerabilities(host))

        return results

    def _parse_host(self, host_elem) -> Dict[str, Any]:
        host_data: Dict[str, Any] = {
            "status": host_elem.find('.//status').get('state') if host_elem.find('.//status') is not None else "unknown",
            "addresses": [],
            "hostnames": [],
            "ports": [],
            "services": [],
            "os": None,
        }

        for addr in host_elem.findall('.//address'):
            host_data["addresses"].append({"addr": addr.get('addr'), "type": addr.get('addrtype')})

        for hn in host_elem.findall('.//hostname'):
            if hn.get('name'):
                host_data["hostnames"].append(hn.get('name'))

        for port in host_elem.findall('.//port'):
            port_data = self._parse_port(port)
            host_data["ports"].append(port_data)
            if port_data.get("service"):
                host_data["services"].append(port_data["service"])

        os_elem = host_elem.find('.//osmatch')
        if os_elem is not None:
            host_data["os"] = {"name": os_elem.get('name'), "accuracy": os_elem.get('accuracy')}

        return host_data

    def _parse_port(self, port_elem) -> Dict[str, Any]:
        state_elem = port_elem.find('.//state')
        service_elem = port_elem.find('.//service')

        port_id = port_elem.get('portid')
        port_data: Dict[str, Any] = {
            "port": int(port_id) if port_id and port_id.isdigit() else port_id,
            "protocol": port_elem.get('protocol'),
            "state": state_elem.get('state') if state_elem is not None else "unknown",
        }

        if service_elem is not None:
            port_data["service"] = {
                "name": service_elem.get('name'),
                "product": service_elem.get('product'),
                "version": service_elem.get('version'),
                "extrainfo": service_elem.get('extrainfo'),
            }

        return port_data

    def _extract_vulnerabilities(self, host_elem) -> List[Dict[str, Any]]:
        vulnerabilities: List[Dict[str, Any]] = []
        for script in host_elem.findall('.//script'):
            script_id = script.get('id', '') or ''
            if 'vuln' in script_id or 'exploit' in script_id:
                output = script.get('output', '') or ''
                cves = re.findall(r'CVE-\d{4}-\d{4,7}', output)
                cvss_score = self._estimate_cvss(output)
                vulnerabilities.append({
                    "id": f"NMAP-{script_id}",
                    "title": script_id.replace('-', ' ').title(),
                    "description": (output[:500]).strip(),
                    "severity": self.get_nvd_severity(cvss_score),
                    "cvss_score": cvss_score,
                    "cve_references": cves,
                    "owasp_category": self._map_to_owasp(script_id),
                    "tool": "nmap",
                    "script": script_id,
                })
        return vulnerabilities

    def _estimate_cvss(self, output: str) -> float:
        out = (output or '').lower()
        if any(w in out for w in ['remote code execution', 'rce', 'critical']):
            return 9.5
        if any(w in out for w in ['sql injection', 'authentication bypass', 'privilege escalation']):
            return 8.0
        if any(w in out for w in ['xss', 'csrf', 'information disclosure']):
            return 5.5
        if any(w in out for w in ['deprecated', 'weak', 'misconfiguration']):
            return 3.0
        return 4.0

    def _map_to_owasp(self, script_id: str) -> str:
        s = (script_id or '').lower()
        if 'sql' in s or 'injection' in s:
            return self.OWASP_MAPPING['sql_injection']
        if 'xss' in s:
            return self.OWASP_MAPPING['xss']
        if 'auth' in s:
            return self.OWASP_MAPPING['auth_bypass']
        if 'access' in s:
            return self.OWASP_MAPPING['broken_access']
        if 'ssl' in s or 'tls' in s:
            return self.OWASP_MAPPING['crypto_fail']
        if 'config' in s:
            return self.OWASP_MAPPING['misconfig']
        if 'version' in s or 'outdated' in s:
            return self.OWASP_MAPPING['outdated']
        return "A04:2021 - Insecure Design"

    # ================== Scan Profiles ==================

    def quick_scan(self) -> Dict[str, Any]:
        # top 100 ports fast
        command = ['nmap', '-T4', '-F', '-oX', '-', self.target_host]
        return self._run_nmap_command(command, "Quick Scan")

    def standard_scan(self) -> Dict[str, Any]:
        # balanced: default scripts + version detection (no -A)
        command = ['nmap', '-T3', '-sV', '--script', 'default', '-oX', '-', self.target_host]
        return self._run_nmap_command(command, "Standard Scan")

    def intense_scan(self) -> Dict[str, Any]:
        # comprehensive (-A enables OS detection, version detection, script scanning, traceroute)
        command = ['nmap', '-T4', '-A', '-v', '-oX', '-', self.target_host]
        return self._run_nmap_command(command, "Intense Scan")

    def comprehensive_scan(self) -> Dict[str, Any]:
        # full port range + version + OS (downgraded automatically if non-root)
        command = ['nmap', '-sS', '-sV', '-O', '-p-', '-oX', '-', self.target_host]
        return self._run_nmap_command(command, "Comprehensive Scan")

    def stealth_scan(self) -> Dict[str, Any]:
        # evasive settings (note: -f fragmentation requires privileges; will still attempt)
        command = ['nmap', '-sS', '-T2', '-f', '--data-length', '200', '-oX', '-', self.target_host]
        return self._run_nmap_command(command, "Stealth Scan")

    def vulnerability_scan(self) -> Dict[str, Any]:
        command = ['nmap', '--script', 'vuln', '-sV', '-oX', '-', self.target_host]
        return self._run_nmap_command(command, "Vulnerability Scan")

    def run_scan(self, scan_type: str) -> Dict[str, Any]:
        scan_type = (scan_type or '').lower()

        scan_methods = {
            'quick': self.quick_scan,
            'standard': self.standard_scan,
            'intense': self.intense_scan,
            'comprehensive': self.comprehensive_scan,
            'stealth': self.stealth_scan,
            'vulnerability': self.vulnerability_scan,
        }

        if scan_type not in scan_methods:
            raise ValueError(f"Invalid scan type. Choose from: {', '.join(scan_methods.keys())}")

        results = scan_methods[scan_type]()
        self.scan_results["results"][scan_type] = results

        if isinstance(results, dict) and "vulnerabilities" in results:
            self.scan_results["vulnerabilities"].extend(results.get("vulnerabilities") or [])

        self._update_summary()
        return results

    def run_all_scans(self) -> Dict[str, Any]:
        for scan_type in ['quick', 'standard', 'intense', 'comprehensive', 'stealth', 'vulnerability']:
            try:
                self.run_scan(scan_type)
            except Exception:
                continue
        return self.scan_results

    def _update_summary(self) -> None:
        summary = {
            "total_vulnerabilities": len(self.scan_results["vulnerabilities"]),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "owasp_breakdown": {},
        }

        for vuln in self.scan_results["vulnerabilities"]:
            sev = (vuln.get("severity") or "INFO").lower()
            if sev in summary:
                summary[sev] += 1
            else:
                summary["info"] += 1

            owasp = vuln.get("owasp_category", "Unknown")
            summary["owasp_breakdown"][owasp] = summary["owasp_breakdown"].get(owasp, 0) + 1

        self.scan_results["summary"] = summary

    def export_json(self, filename: Optional[str] = None) -> str:
        if not filename:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            safe_host = re.sub(r'[^a-zA-Z0-9._-]', '_', self.target_host)
            filename = f"nmap_scan_{safe_host}_{timestamp}.json"

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.scan_results, f, indent=2, ensure_ascii=False)

        return filename


def run_nmap(target: str, scan_type: str = 'standard') -> Dict[str, Any]:
    """Convenience wrapper — creates an NmapScanner and returns scan_results."""
    scanner = NmapScanner(target)
    scanner.run_scan(scan_type)
    return scanner.scan_results


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Nmap Integration Script - curated scan profiles with JSON output',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('target', help='Target URL or IP address (e.g., https://example.com)')
    parser.add_argument('scan_type', choices=['quick', 'standard', 'intense', 'comprehensive', 'stealth', 'vulnerability', 'all'])
    parser.add_argument('-o', '--output', help='Output JSON filename')
    parser.add_argument('--pretty', action='store_true', help='Pretty print JSON to console')

    args = parser.parse_args()

    try:
        subprocess.run(['nmap', '--version'], capture_output=True, check=True)
    except Exception:
        print("[!] Error: Nmap is not installed or not in PATH", file=sys.stderr)
        sys.exit(1)

    scanner = NmapScanner(args.target)

    if args.scan_type == 'all':
        scanner.run_all_scans()
    else:
        scanner.run_scan(args.scan_type)

    out_file = scanner.export_json(args.output)

    if args.pretty:
        print(json.dumps(scanner.scan_results, indent=2, ensure_ascii=False))

    # Minimal summary to stdout (for backend logs)
    summary = scanner.scan_results.get("summary", {})
    print(f"[✓] Complete! Results saved to: {out_file}")
    print(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")


if __name__ == '__main__':
    main()
