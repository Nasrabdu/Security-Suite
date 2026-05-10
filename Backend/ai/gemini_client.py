"""
Google Gemini AI Client for Pentest Platform
Uses ONLY real scan data — never fabricates results.
GEMINI_API_KEY must be set in the environment; falls back to rule-based analysis if absent.
"""

import json
import os
import re
from typing import Any, Dict, List, Optional


class GeminiClient:
    """Wrapper around Google Gemini API for security analysis."""

    def __init__(self):
        self.api_key = os.environ.get('GEMINI_API_KEY', '')
        self.model = None
        self._initialized = False

        if self.api_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel('gemini-1.5-flash')
                self._initialized = True
                print("✓ Gemini AI client initialized")
            except Exception as e:
                print(f"⚠ Gemini AI init failed: {e}")
        else:
            print("⚠ GEMINI_API_KEY not set — AI features will use fallback mode")

    def is_available(self) -> bool:
        return self._initialized and self.model is not None

    def _generate(self, prompt: str, temperature: float = 0.3) -> Optional[str]:
        """Send a prompt to Gemini and return the text response."""
        if not self.is_available():
            return None
        try:
            import google.generativeai as genai
            generation_config = genai.types.GenerationConfig(
                temperature=temperature,
                max_output_tokens=4096,
            )
            response = self.model.generate_content(prompt, generation_config=generation_config)
            return response.text
        except Exception as e:
            print(f"Gemini API error: {e}")
            return None

    def _extract_json(self, text: str) -> Optional[Dict]:
        """Extract JSON from a text response, handling markdown code fences."""
        if not text:
            return None
        # Strip markdown code fences if present
        text = re.sub(r'^```(?:json)?\s*', '', text.strip(), flags=re.MULTILINE)
        text = re.sub(r'```\s*$', '', text.strip(), flags=re.MULTILINE)
        text = text.strip()
        try:
            return json.loads(text)
        except Exception:
            # Try to find JSON block within text
            match = re.search(r'\{[\s\S]+\}', text)
            if match:
                try:
                    return json.loads(match.group())
                except Exception:
                    pass
        return None

    def summarize_scan(self, scan_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Summarize scan results using Gemini.
        scan_data must be real data from nmap scanner.
        Returns structured summary dict.
        """
        if not self.is_available():
            return None

        ports = _extract_ports_from_scan(scan_data)
        vulns = scan_data.get('vulnerabilities', [])
        target = scan_data.get('scan_metadata', {}).get('target', scan_data.get('target', 'unknown'))

        prompt = f"""You are a senior cybersecurity analyst. Analyze this REAL Nmap scan data and provide a security summary.

TARGET: {target}
OPEN PORTS ({len(ports)}):
{_format_ports(ports)}

VULNERABILITIES DETECTED ({len(vulns)}):
{_format_vulns(vulns)}

Respond with ONLY valid JSON (no markdown) in exactly this structure:
{{
  "risk_level": "critical|high|medium|low|info",
  "risk_score": 0-100,
  "summary": "2-3 sentence professional summary of findings",
  "key_findings": ["finding1", "finding2", "finding3"],
  "recommendations": ["action1", "action2", "action3"]
}}

Rules:
- Base everything on the REAL data above only
- risk_score: critical findings = 75-100, high = 50-74, medium = 25-49, low = 10-24, info = 0-9
- Be specific about actual services and ports found
"""
        text = self._generate(prompt)
        result = self._extract_json(text)
        return result

    def generate_full_report(self, scan_data: Dict[str, Any], vulnerabilities: List[Dict]) -> Optional[Dict[str, Any]]:
        """
        Generate a comprehensive AI security report.
        Uses ONLY real scan data passed in.
        """
        if not self.is_available():
            return None

        ports = _extract_ports_from_scan(scan_data)
        target = scan_data.get('scan_metadata', {}).get('target', scan_data.get('target', 'unknown'))
        scan_type = scan_data.get('scan_metadata', {}).get('scan_type', scan_data.get('scan_type', 'unknown'))
        duration = scan_data.get('duration', 'N/A')

        prompt = f"""You are a senior penetration tester writing a professional security assessment report.

IMPORTANT: Use ONLY the real scan data provided below. Do NOT invent ports, services, or vulnerabilities.

=== SCAN METADATA ===
Target: {target}
Scan Type: {scan_type}
Duration: {duration}s
Scanner: Nmap

=== OPEN PORTS FOUND ({len(ports)}) ===
{_format_ports(ports)}

=== VULNERABILITIES IDENTIFIED ({len(vulnerabilities)}) ===
{_format_vulns_detailed(vulnerabilities)}

Generate a comprehensive security report as ONLY valid JSON (no markdown):
{{
  "executive_summary": "3-5 sentence professional executive summary based on REAL findings",
  "risk_score": 0-100,
  "risk_grade": "A|B|C|D|F",
  "risk_level": "critical|high|medium|low|info",
  "threat_narrative": "2-3 paragraph narrative about the security posture discovered",
  "severity_distribution": {{
    "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
  }},
  "top_findings": [
    {{
      "title": "Finding title",
      "severity": "high|medium|low|critical|info",
      "description": "Detailed description based on real findings",
      "impact": "What an attacker could do with this",
      "affected_component": "Port/Service name",
      "remediation": "Specific actionable fix"
    }}
  ],
  "recommendations": [
    {{
      "priority": "critical|high|medium|low",
      "action": "Specific actionable recommendation",
      "effort": "low|medium|high",
      "impact_reduction": "How this reduces risk"
    }}
  ],
  "port_risk_data": [
    {{
      "port": 80,
      "service": "http",
      "risk_level": "medium",
      "risk_score": 50,
      "risk_reason": "Why this port poses a risk"
    }}
  ],
  "attack_surface_summary": {{
    "total_open_ports": {len(ports)},
    "high_risk_services": 0,
    "outdated_services": 0,
    "encrypted_services": 0,
    "unencrypted_services": 0
  }},
  "compliance_notes": [
    "Specific compliance note relevant to findings"
  ],
  "mitigation_roadmap": [
    {{
      "phase": "Immediate (0-7 days)",
      "actions": ["action1"]
    }},
    {{
      "phase": "Short-term (1-4 weeks)",
      "actions": ["action1"]
    }},
    {{
      "phase": "Long-term (1-3 months)",
      "actions": ["action1"]
    }}
  ]
}}

Risk grade: A=0-20, B=21-40, C=41-60, D=61-80, F=81-100
Base ALL analysis on the REAL data provided. Return ONLY valid JSON.
CRITICAL: Write all narrative text (executive_summary, threat_narrative, description, impact, remediation, action, phase, compliance notes) in BOTH Arabic and English. (e.g., 'English text. / النص العربي.')"""

        text = self._generate(prompt, temperature=0.4)
        result = self._extract_json(text)
        return result

    def analyze_scan(self, scan_data: Dict[str, Any],
                     vulnerabilities: List[Dict] = None) -> Dict[str, Any]:
        """
        Main public entry point for scan analysis.
        Calls generate_full_report when vulnerabilities are provided,
        otherwise calls summarize_scan. Falls back to rule-based summary
        if Gemini is unavailable or returns nothing.
        """
        if self.is_available():
            if vulnerabilities:
                result = self.generate_full_report(scan_data, vulnerabilities)
            else:
                result = self.summarize_scan(scan_data)
            if result:
                return result
        return self._fallback_summary(scan_data)

    def _fallback_summary(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Rule-based summary used when Gemini is unavailable."""
        ports  = _extract_ports_from_scan(scan_data)
        target = (scan_data.get('scan_metadata') or {}).get('target', scan_data.get('target', 'unknown'))
        return {
            'risk_level':       'info',
            'risk_score':       10,
            'summary':          f'Scan of {target} completed. Found {len(ports)} open port(s). '
                                 'Set GEMINI_API_KEY for AI analysis.',
            'key_findings':     [f'{len(ports)} open port(s) discovered'],
            'recommendations':  ['Review all open ports', 'Update all services', 'Configure firewall'],
            'ai_generated':     False,
        }

    def generate_json(self, prompt: str, system_prompt: str = None,
                      temperature: float = 0.3) -> Optional[Dict]:
        """
        Generate a JSON response from Gemini, optionally prepending a system prompt.
        Accepts an optional system_prompt prepended to the user prompt.
        """
        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        text = self._generate(full_prompt, temperature=temperature)
        return self._extract_json(text)


# ─────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────

def _extract_ports_from_scan(scan_data: Dict) -> List[Dict]:
    """Extract all port entries from various scan data shapes."""
    ports = []
    # Shape 1: scan_data["results"][scan_type]["ports"]
    results = scan_data.get('results', {})
    if isinstance(results, dict):
        for key, val in results.items():
            if isinstance(val, dict):
                ports.extend(val.get('ports', []))
    # Shape 2: ports directly on scan_data
    if not ports:
        ports = scan_data.get('ports', [])
    return ports


def _format_ports(ports: List[Dict]) -> str:
    if not ports:
        return "  (No open ports found)"
    lines = []
    for p in ports[:30]:
        port = p.get('port', '?')
        proto = p.get('protocol', 'tcp')
        state = p.get('state', '?')
        svc = p.get('service', {})
        if isinstance(svc, dict):
            svc_name = svc.get('name', 'unknown')
            svc_ver = svc.get('version', '')
            product = svc.get('product', '')
            svc_str = f"{svc_name}"
            if product:
                svc_str += f" ({product}"
                if svc_ver:
                    svc_str += f" {svc_ver}"
                svc_str += ")"
        else:
            svc_str = str(svc) if svc else 'unknown'
        lines.append(f"  Port {port}/{proto} [{state}]: {svc_str}")
    return "\n".join(lines)


def _format_vulns(vulns: List[Dict]) -> str:
    if not vulns:
        return "  (No vulnerabilities detected by scanner)"
    lines = []
    for v in vulns[:15]:
        sev = v.get('severity', 'info').upper()
        title = v.get('title', v.get('id', 'Unknown'))
        lines.append(f"  [{sev}] {title}")
    return "\n".join(lines)


def _format_vulns_detailed(vulns: List[Dict]) -> str:
    if not vulns:
        return "  (No vulnerabilities detected by scanner)"
    lines = []
    for v in vulns[:15]:
        sev = v.get('severity', 'info').upper()
        title = v.get('title', v.get('id', 'Unknown'))
        desc = v.get('description', '')[:200]
        cve = v.get('cve_id') or v.get('cve_references', [None])[0] if v.get('cve_references') else None
        line = f"  [{sev}] {title}"
        if cve:
            line += f" ({cve})"
        if desc:
            line += f"\n    {desc}"
        lines.append(line)
    return "\n".join(lines)


# Singleton
_gemini_client: Optional[GeminiClient] = None


def get_gemini_client() -> GeminiClient:
    global _gemini_client
    if _gemini_client is None:
        _gemini_client = GeminiClient()
    return _gemini_client
