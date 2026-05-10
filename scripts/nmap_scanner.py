#!/usr/bin/env python3
"""
Nmap Integration Script for Security Suite
Optimized for Kali Linux
Supports 5 best Nmap scanning commands with JSON output
"""

import json
import subprocess
import sys
import argparse
from datetime import datetime
import xml.etree.ElementTree as ET
import re
import os
from typing import Dict, List, Any

class NmapScanner:


def _downgrade_if_unprivileged(self, command: list[str]) -> list[str]:
    # إذا ما كان التشغيل بصلاحيات root
    if os.geteuid() != 0:
        # -sS يحتاج raw sockets → استبدله بـ -sT
        command = ['-sT' if x == '-sS' else x for x in command]

        # إزالة OS detection إذا موجود
        command = [x for x in command if x != '-O']

    return command

    """Nmap scanner with 5 optimized scanning profiles"""
    
    # OWASP Top 10 2021 Mapping
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
        'integrity': 'A08:2021 - Software and Data Integrity Failures'
    }
    
    # NVD Severity Scoring
    @staticmethod
    def get_nvd_severity(cvss_score: float) -> str:
        """Get NVD severity classification"""
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        elif cvss_score > 0:
            return "LOW"
        return "INFO"
    
    def __init__(self, target: str):
        """Initialize scanner with target URL/IP"""
        self.target = self._extract_host(target)
        self.scan_results = {
            "scan_metadata": {
                "target": target,
                "target_host": self.target,
                "scan_date": datetime.utcnow().isoformat() + "Z",
                "scanner": "nmap",
                "version": self._get_nmap_version()
            },
            "results": {},
            "vulnerabilities": [],
            "summary": {
                "total_vulnerabilities": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }
    
    def _extract_host(self, url: str) -> str:
        """Extract hostname/IP from URL"""
        # Remove protocol
        host = re.sub(r'^https?://', '', url)
        # Remove path
        host = host.split('/')[0]
        # Remove port
        host = host.split(':')[0]
        return host
    
    def _get_nmap_version(self) -> str:
        """Get Nmap version"""
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            version_line = result.stdout.split('\n')[0]
            return version_line.replace('Nmap version ', '')
        except:
            return "Unknown"
    
    def _run_nmap_command(self, command: List[str], scan_name: str) -> Dict[str, Any]:
        """Execute Nmap command and return results"""
        print(f"[*] Running {scan_name}...")
        print(f"[*] Command: {' '.join(command)}")
        command = self._downgrade_if_unprivileged(command)

        
        start_time = datetime.utcnow()
        
        try:
            # Run Nmap with XML output
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            
            if result.returncode != 0:
                return {
                    "status": "failed",
                    "error": result.stderr,
                    "duration": duration
                }
            
            # Parse XML output
            parsed_results = self._parse_nmap_xml(result.stdout)
            parsed_results["duration"] = duration
            parsed_results["status"] = "completed"
            parsed_results["command"] = ' '.join(command)
            
            print(f"[✓] {scan_name} completed in {duration:.2f}s")
            return parsed_results
            
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "error": "Scan exceeded 5 minute timeout",
                "duration": 300
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "duration": 0
            }
    
    def _parse_nmap_xml(self, xml_output: str) -> Dict[str, Any]:
        """Parse Nmap XML output"""
        try:
            root = ET.fromstring(xml_output)
        except:
            # If XML parsing fails, return raw output
            return {"raw_output": xml_output, "parsed": False}
        
        results = {
            "parsed": True,
            "hosts": [],
            "ports": [],
            "services": [],
            "os_detection": None,
            "vulnerabilities": []
        }
        
        # Parse hosts
        for host in root.findall('.//host'):
            host_data = self._parse_host(host)
            results["hosts"].append(host_data)
            results["ports"].extend(host_data.get("ports", []))
            results["services"].extend(host_data.get("services", []))
            
            # Extract vulnerabilities from script output
            vulns = self._extract_vulnerabilities(host)
            results["vulnerabilities"].extend(vulns)
        
        return results
    
    def _parse_host(self, host_elem) -> Dict[str, Any]:
        """Parse individual host element"""
        host_data = {
            "status": host_elem.find('.//status').get('state') if host_elem.find('.//status') is not None else "unknown",
            "addresses": [],
            "hostnames": [],
            "ports": [],
            "services": [],
            "os": None
        }
        
        # Addresses
        for addr in host_elem.findall('.//address'):
            host_data["addresses"].append({
                "addr": addr.get('addr'),
                "type": addr.get('addrtype')
            })
        
        # Hostnames
        for hostname in host_elem.findall('.//hostname'):
            host_data["hostnames"].append(hostname.get('name'))
        
        # Ports and Services
        for port in host_elem.findall('.//port'):
            port_data = self._parse_port(port)
            host_data["ports"].append(port_data)
            if port_data.get("service"):
                host_data["services"].append(port_data["service"])
        
        # OS Detection
        os_elem = host_elem.find('.//osmatch')
        if os_elem is not None:
            host_data["os"] = {
                "name": os_elem.get('name'),
                "accuracy": os_elem.get('accuracy')
            }
        
        return host_data
    
    def _parse_port(self, port_elem) -> Dict[str, Any]:
        """Parse port element"""
        state_elem = port_elem.find('.//state')
        service_elem = port_elem.find('.//service')
        
        port_data = {
            "port": port_elem.get('portid'),
            "protocol": port_elem.get('protocol'),
            "state": state_elem.get('state') if state_elem is not None else "unknown"
        }
        
        if service_elem is not None:
            port_data["service"] = {
                "name": service_elem.get('name'),
                "product": service_elem.get('product'),
                "version": service_elem.get('version'),
                "extrainfo": service_elem.get('extrainfo')
            }
        
        return port_data
    
    def _extract_vulnerabilities(self, host_elem) -> List[Dict[str, Any]]:
        """Extract vulnerabilities from NSE script output"""
        vulnerabilities = []
        
        for script in host_elem.findall('.//script'):
            script_id = script.get('id', '')
            
            # Check if it's a vulnerability script
            if 'vuln' in script_id or 'exploit' in script_id:
                output = script.get('output', '')
                
                # Parse CVE references
                cve_pattern = r'CVE-\d{4}-\d{4,7}'
                cves = re.findall(cve_pattern, output)
                
                # Estimate CVSS score based on keywords
                cvss_score = self._estimate_cvss(output)
                
                vuln = {
                    "id": f"NMAP-{script_id}",
                    "title": script_id.replace('-', ' ').title(),
                    "description": output[:200],  # First 200 chars
                    "severity": self.get_nvd_severity(cvss_score),
                    "cvss_score": cvss_score,
                    "cve_references": cves,
                    "owasp_category": self._map_to_owasp(script_id),
                    "tool": "nmap",
                    "script": script_id
                }
                
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _estimate_cvss(self, output: str) -> float:
        """Estimate CVSS score from vulnerability description"""
        output_lower = output.lower()
        
        # Critical indicators
        if any(word in output_lower for word in ['remote code execution', 'rce', 'critical']):
            return 9.5
        
        # High indicators
        if any(word in output_lower for word in ['sql injection', 'authentication bypass', 'privilege escalation']):
            return 8.0
        
        # Medium indicators
        if any(word in output_lower for word in ['xss', 'csrf', 'information disclosure']):
            return 5.5
        
        # Low indicators
        if any(word in output_lower for word in ['deprecated', 'weak', 'misconfiguration']):
            return 3.0
        
        return 4.0  # Default medium
    
    def _map_to_owasp(self, script_id: str) -> str:
        """Map vulnerability to OWASP Top 10 category"""
        script_lower = script_id.lower()
        
        if 'sql' in script_lower or 'injection' in script_lower:
            return self.OWASP_MAPPING['sql_injection']
        elif 'xss' in script_lower:
            return self.OWASP_MAPPING['xss']
        elif 'auth' in script_lower:
            return self.OWASP_MAPPING['auth_bypass']
        elif 'access' in script_lower:
            return self.OWASP_MAPPING['broken_access']
        elif 'ssl' in script_lower or 'tls' in script_lower:
            return self.OWASP_MAPPING['crypto_fail']
        elif 'config' in script_lower:
            return self.OWASP_MAPPING['misconfig']
        elif 'version' in script_lower or 'outdated' in script_lower:
            return self.OWASP_MAPPING['outdated']
        
        return "A04:2021 - Insecure Design"  # Default
    
    # ========== 5 BEST NMAP COMMANDS ==========
    
    def quick_scan(self) -> Dict[str, Any]:
        """
        Command 1: Quick Scan
        Fast reconnaissance of top 100 ports
        """
        command = ['nmap', '-T4', '-F', '-oX', '-', self.target]
        return self._run_nmap_command(command, "Quick Scan")
    
    def intense_scan(self) -> Dict[str, Any]:
        """
        Command 2: Intense Scan
        Comprehensive analysis with OS detection, version detection, scripts
        """
        command = ['nmap', '-T4', '-A', '-v', '-oX', '-', self.target]
        return self._run_nmap_command(command, "Intense Scan")
    
    def comprehensive_scan(self) -> Dict[str, Any]:
        """
        Command 3: Comprehensive Port Scan
        Full port range scan with version detection
        """
        command = ['nmap', '-sS', '-sV', '-O', '-p-', '-oX', '-', self.target]
        return self._run_nmap_command(command, "Comprehensive Scan")
    
    def stealth_scan(self) -> Dict[str, Any]:
        """
        Command 4: Stealth Scan
        Evasive scanning to avoid IDS/IPS detection
        """
        command = ['nmap', '-sS', '-T2', '-f', '--data-length', '200', '-oX', '-', self.target]
        return self._run_nmap_command(command, "Stealth Scan")
    
    def vulnerability_scan(self) -> Dict[str, Any]:
        """
        Command 5: Vulnerability Scan
        NSE vulnerability scripts for security assessment
        """
        command = ['nmap', '--script', 'vuln', '-sV', '-oX', '-', self.target]
        return self._run_nmap_command(command, "Vulnerability Scan")
    
    def run_scan(self, scan_type: str) -> Dict[str, Any]:
        """Run specified scan type"""
        scan_methods = {
            'quick': self.quick_scan,
            'intense': self.intense_scan,
            'comprehensive': self.comprehensive_scan,
            'stealth': self.stealth_scan,
            'vulnerability': self.vulnerability_scan
        }
        
        if scan_type not in scan_methods:
            raise ValueError(f"Invalid scan type. Choose from: {', '.join(scan_methods.keys())}")
        
        # Run the scan
        results = scan_methods[scan_type]()
        
        # Update scan results
        self.scan_results["results"][scan_type] = results
        
        # Aggregate vulnerabilities
        if "vulnerabilities" in results:
            self.scan_results["vulnerabilities"].extend(results["vulnerabilities"])
        
        # Update summary
        self._update_summary()
        
        return results
    
    def run_all_scans(self) -> Dict[str, Any]:
        """Run all 5 scan types"""
        print("[*] Running all 5 Nmap scan profiles...")
        
        for scan_type in ['quick', 'intense', 'comprehensive', 'stealth', 'vulnerability']:
            try:
                self.run_scan(scan_type)
            except Exception as e:
                print(f"[!] Error in {scan_type} scan: {e}")
        
        return self.scan_results
    
    def _update_summary(self):
        """Update vulnerability summary"""
        summary = {
            "total_vulnerabilities": len(self.scan_results["vulnerabilities"]),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "owasp_breakdown": {},
            "nvd_breakdown": {}
        }
        
        for vuln in self.scan_results["vulnerabilities"]:
            severity = vuln.get("severity", "INFO").upper()
            summary[severity.lower()] = summary.get(severity.lower(), 0) + 1
            
            # OWASP breakdown
            owasp = vuln.get("owasp_category", "Unknown")
            summary["owasp_breakdown"][owasp] = summary["owasp_breakdown"].get(owasp, 0) + 1
        
        self.scan_results["summary"] = summary
    
    def export_json(self, filename: str = None) -> str:
        """Export results to JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"nmap_scan_{self.target}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.scan_results, f, indent=2)
        
        print(f"[✓] Results exported to {filename}")
        return filename


def main():
    parser = argparse.ArgumentParser(
        description='Nmap Integration Script - 5 Best Scanning Commands',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scan Types:
  quick          Fast scan of top 100 ports (-T4 -F)
  intense        Comprehensive scan with OS/version detection (-T4 -A -v)
  comprehensive  Full port range scan (-sS -sV -O -p-)
  stealth        Evasive scan to avoid detection (-sS -T2 -f)
  vulnerability  NSE vulnerability scripts (--script vuln -sV)
  all            Run all 5 scan types

Examples:
  python3 nmap_scanner.py https://example.com quick
  python3 nmap_scanner.py 192.168.1.1 vulnerability
  python3 nmap_scanner.py example.com all --output results.json
        """
    )
    
    parser.add_argument('target', help='Target URL or IP address')
    parser.add_argument('scan_type', 
                       choices=['quick','standard', 'intense', 'comprehensive', 'stealth', 'vulnerability', 'all'],
                       help='Type of scan to perform')
    parser.add_argument('-o', '--output', help='Output JSON filename')
    parser.add_argument('--pretty', action='store_true', help='Pretty print JSON to console')
    
# بعد parse_args
scan_type = args.scan_type
    args = parser.parse_args()
if scan_type == 'standard':
    scan_type = 'intense'
    

    
    # Check if Nmap is installed
    try:
        subprocess.run(['nmap', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[!] Error: Nmap is not installed or not in PATH")
        print("[*] On Kali Linux, Nmap should be pre-installed")
        sys.exit(1)
    
    # Initialize scanner
    scanner = NmapScanner(args.target)
    
    # Run scan
    if args.scan_type == 'all':
        scanner.run_all_scans()
    else:
        scanner.run_scan(args.scan_type)
    
    # Export results
    output_file = scanner.export_json(args.output)
    
    # Pretty print if requested
    if args.pretty:
        print("\n" + "="*80)
        print("SCAN RESULTS")
        print("="*80)
        print(json.dumps(scanner.scan_results, indent=2))
    
    # Print summary
    print("\n" + "="*80)
    print("VULNERABILITY SUMMARY")
    print("="*80)
    summary = scanner.scan_results["summary"]
    print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
    print(f"  Critical: {summary['critical']}")
    print(f"  High:     {summary['high']}")
    print(f"  Medium:   {summary['medium']}")
    print(f"  Low:      {summary['low']}")
    print(f"  Info:     {summary['info']}")
    
    if summary.get('owasp_breakdown'):
        print("\nOWASP Top 10 Breakdown:")
        for category, count in summary['owasp_breakdown'].items():
            print(f"  {category}: {count}")
    
    print(f"\n[✓] Complete! Results saved to: {output_file}")


if __name__ == '__main__':
    main()
