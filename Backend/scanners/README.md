# Nmap Integration Scripts

This directory contains Python and Bash scripts for integrating Nmap scanning into the Security Suite.

## Files

### 1. `nmap_scanner.py` - Python Nmap Scanner
Comprehensive Python script with 5 optimized Nmap scanning profiles, OWASP Top 10 mapping, and NVD severity classification.

**Features:**
- 5 best Nmap scanning commands
- XML output parsing
- JSON export
- OWASP Top 10 2021 vulnerability mapping
- NVD severity scoring (Critical/High/Medium/Low)
- CVE reference extraction
- CVSS score estimation

**Requirements:**
```bash
# Nmap must be installed (pre-installed on Kali Linux)
sudo apt update
sudo apt install nmap python3
```

**Usage:**
```bash
# Quick scan
python3 nmap_scanner.py https://example.com quick

# Intense scan with all features
python3 nmap_scanner.py 192.168.1.1 intense

# Vulnerability scan
python3 nmap_scanner.py example.com vulnerability

# Run all 5 scans
python3 nmap_scanner.py https://example.com all

# Export to custom JSON file
python3 nmap_scanner.py https://example.com all --output my_scan.json

# Pretty print results to console
python3 nmap_scanner.py https://example.com quick --pretty
```

**Scan Types:**
1. **quick** - Fast scan of top 100 ports (`-T4 -F`)
2. **intense** - Comprehensive with OS/version detection (`-T4 -A -v`)
3. **comprehensive** - Full port range scan (`-sS -sV -O -p-`)
4. **stealth** - Evasive IDS/IPS avoidance (`-sS -T2 -f`)
5. **vulnerability** - NSE vulnerability scripts (`--script vuln -sV`)

### 2. `nmap_scan.sh` - Bash Wrapper Script
Quick access wrapper for Nmap commands with JSON export support.

**Make it executable:**
```bash
chmod +x nmap_scan.sh
```

**Usage:**
```bash
# Quick scan
./nmap_scan.sh example.com 1

# Intense scan
./nmap_scan.sh 192.168.1.1 2

# Vulnerability scan with JSON output
./nmap_scan.sh https://example.com 5 --json

# Save to custom file
./nmap_scan.sh example.com 1 -o results.txt
```

**Scan Numbers:**
- `1` or `quick` - Quick scan
- `2` or `intense` - Intense scan
- `3` or `comprehensive` - Comprehensive scan
- `4` or `stealth` - Stealth scan
- `5` or `vulnerability` - Vulnerability scan

## JSON Output Format

```json
{
  "scan_metadata": {
    "target": "https://example.com",
    "target_host": "example.com",
    "scan_date": "2026-02-15T18:30:00Z",
    "scanner": "nmap",
    "version": "7.94"
  },
  "results": {
    "quick": {
      "status": "completed",
      "duration": 3.42,
      "command": "nmap -T4 -F -oX - example.com",
      "hosts": [...],
      "ports": [...],
      "services": [...]
    }
  },
  "vulnerabilities": [
    {
      "id": "NMAP-http-vuln-cve2021-12345",
      "title": "HTTP Vulnerability",
      "description": "...",
      "severity": "HIGH",
      "cvss_score": 8.0,
      "cve_references": ["CVE-2021-12345"],
      "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
      "tool": "nmap",
      "script": "http-vuln-cve2021-12345"
    }
  ],
  "summary": {
    "total_vulnerabilities": 5,
    "critical": 1,
    "high": 2,
    "medium": 2,
    "low": 0,
    "info": 0,
    "owasp_breakdown": {
      "A03:2021 - Injection": 2,
      "A06:2021 - Vulnerable and Outdated Components": 3
    }
  }
}
```

## OWASP Top 10 2021 Mapping

The scanner automatically maps discovered vulnerabilities to OWASP Top 10 categories:

- **A01:2021** - Broken Access Control
- **A02:2021** - Cryptographic Failures
- **A03:2021** - Injection
- **A04:2021** - Insecure Design
- **A05:2021** - Security Misconfiguration
- **A06:2021** - Vulnerable and Outdated Components
- **A07:2021** - Identification and Authentication Failures
- **A08:2021** - Software and Data Integrity Failures
- **A09:2021** - Security Logging and Monitoring Failures
- **A10:2021** - Server-Side Request Forgery (SSRF)

## NVD Severity Scoring

Vulnerabilities are classified using NVD CVSS v3 severity ratings:

- **CRITICAL**: 9.0-10.0
- **HIGH**: 7.0-8.9
- **MEDIUM**: 4.0-6.9
- **LOW**: 0.1-3.9
- **INFO**: 0.0

## Integration with Web Interface

To integrate these scripts with the web interface:

1. **Backend API** (PHP/Node.js/Python Flask):
   ```python
   # Example Flask endpoint
   @app.route('/api/scan', methods=['POST'])
   def start_scan():
       target = request.json['target']
       scan_type = request.json['scan_type']
       
       # Run scanner
       result = subprocess.run([
           'python3', 'scripts/nmap_scanner.py',
           target, scan_type, '--output', f'scans/{uuid.uuid4()}.json'
       ], capture_output=True)
       
       return jsonify({'status': 'started', 'scan_id': scan_id})
   ```

2. **Frontend JavaScript**:
   ```javascript
   // Start scan
   fetch('/api/scan', {
       method: 'POST',
       headers: {'Content-Type': 'application/json'},
       body: JSON.stringify({
           target: 'https://example.com',
           scan_type: 'quick'
       })
   }).then(response => response.json())
     .then(data => console.log('Scan started:', data.scan_id));
   ```

## Security Considerations

⚠️ **IMPORTANT**: Only scan systems you have explicit permission to test!

- Unauthorized scanning is illegal
- Always obtain written authorization
- Use appropriate scan timing to avoid DoS
- Respect rate limits and target capacity
- Store results securely
- Implement proper access controls

## Troubleshooting

### Nmap not found
```bash
# Install Nmap
sudo apt update
sudo apt install nmap
```

### Permission denied
```bash
# Some scans require root privileges
sudo python3 nmap_scanner.py example.com comprehensive
```

### XML parsing errors
- Ensure Nmap version is 7.0 or higher
- Check that `-oX -` flag is working correctly
- Verify Python xml.etree.ElementTree is available

## Examples

### Example 1: Quick Security Assessment
```bash
# Fast scan to identify open ports and services
python3 nmap_scanner.py https://mywebsite.com quick --pretty
```

### Example 2: Comprehensive Vulnerability Scan
```bash
# Full vulnerability assessment
python3 nmap_scanner.py 192.168.1.100 vulnerability -o vuln_report.json
```

### Example 3: Stealth Reconnaissance
```bash
# Evasive scan to avoid detection
python3 nmap_scanner.py target.com stealth
```

### Example 4: Complete Security Audit
```bash
# Run all 5 scan types
python3 nmap_scanner.py https://example.com all -o complete_audit.json --pretty
```

## License

These scripts are part of the Security Suite project. Use responsibly and ethically.

## Support

For issues or questions:
1. Check Nmap documentation: https://nmap.org/docs.html
2. Review OWASP Top 10: https://owasp.org/Top10/
3. Consult NVD documentation: https://nvd.nist.gov/
