"""
OWASP Top 10 2021 Mapper
Map vulnerabilities to OWASP categories
"""

from typing import Dict, Optional, List

# OWASP Top 10 2021 Categories
OWASP_TOP_10_2021 = {
    'A01:2021': {
        'name': 'Broken Access Control',
        'description': 'Restrictions on what authenticated users are allowed to do are often not properly enforced',
        'examples': ['Unauthorized access', 'Privilege escalation', 'CORS misconfiguration'],
        'remediation': 'Implement proper access controls, deny by default, use RBAC'
    },
    'A02:2021': {
        'name': 'Cryptographic Failures',
        'description': 'Failures related to cryptography which often lead to exposure of sensitive data',
        'examples': ['Weak encryption', 'Plaintext transmission', 'Weak hashing'],
        'remediation': 'Use strong encryption, TLS for data in transit, secure key management'
    },
    'A03:2021': {
        'name': 'Injection',
        'description': 'User-supplied data is not validated, filtered, or sanitized',
        'examples': ['SQL injection', 'Command injection', 'LDAP injection'],
        'remediation': 'Use parameterized queries, input validation, escape special characters'
    },
    'A04:2021': {
        'name': 'Insecure Design',
        'description': 'Missing or ineffective control design',
        'examples': ['Missing rate limiting', 'Insecure architecture', 'Threat modeling gaps'],
        'remediation': 'Implement secure design patterns, threat modeling, security requirements'
    },
    'A05:2021': {
        'name': 'Security Misconfiguration',
        'description': 'Missing appropriate security hardening or improperly configured permissions',
        'examples': ['Default credentials', 'Unnecessary features enabled', 'Verbose errors'],
        'remediation': 'Harden configurations, disable unnecessary features, regular security reviews'
    },
    'A06:2021': {
        'name': 'Vulnerable and Outdated Components',
        'description': 'Using components with known vulnerabilities',
        'examples': ['Outdated libraries', 'Unpatched software', 'EOL components'],
        'remediation': 'Keep components updated, remove unused dependencies, monitor CVEs'
    },
    'A07:2021': {
        'name': 'Identification and Authentication Failures',
        'description': 'Confirmation of user identity, authentication, and session management',
        'examples': ['Weak passwords', 'Session fixation', 'Missing MFA'],
        'remediation': 'Implement MFA, strong password policies, secure session management'
    },
    'A08:2021': {
        'name': 'Software and Data Integrity Failures',
        'description': 'Code and infrastructure that does not protect against integrity violations',
        'examples': ['Unsigned updates', 'Insecure CI/CD', 'Untrusted sources'],
        'remediation': 'Use digital signatures, verify integrity, secure CI/CD pipeline'
    },
    'A09:2021': {
        'name': 'Security Logging and Monitoring Failures',
        'description': 'Insufficient logging and monitoring',
        'examples': ['No audit logs', 'Inadequate monitoring', 'No alerting'],
        'remediation': 'Implement comprehensive logging, real-time monitoring, alerting'
    },
    'A10:2021': {
        'name': 'Server-Side Request Forgery (SSRF)',
        'description': 'Fetching a remote resource without validating the user-supplied URL',
        'examples': ['SSRF attacks', 'Internal network scanning', 'Cloud metadata access'],
        'remediation': 'Validate and sanitize URLs, use allowlists, network segmentation'
    }
}


def map_service_to_owasp(service: str, port: int, version: str = "") -> Optional[str]:
    """
    Map a service to OWASP category based on common patterns
    
    Args:
        service: Service name
        port: Port number
        version: Service version
    
    Returns:
        str: OWASP category ID (e.g., 'A05:2021')
    """
    service_lower = service.lower()
    
    # Unencrypted protocols -> Cryptographic Failures
    if service_lower in ['telnet', 'ftp', 'http'] or port in [21, 23, 80]:
        return 'A02:2021'
    
    # Database services -> Injection risk
    if service_lower in ['mysql', 'postgresql', 'mssql', 'mongodb']:
        return 'A03:2021'
    
    # Authentication services -> Authentication Failures
    if service_lower in ['ldap', 'kerberos', 'radius'] or port in [389, 88, 1812]:
        return 'A07:2021'
    
    # Outdated/vulnerable versions -> Vulnerable Components
    if version and ('old' in version.lower() or 'outdated' in version.lower()):
        return 'A06:2021'
    
    # Default: Security Misconfiguration
    return 'A05:2021'


def get_owasp_info(category_id: str) -> Optional[Dict]:
    """
    Get detailed information about an OWASP category
    
    Args:
        category_id: OWASP category ID (e.g., 'A03:2021')
    
    Returns:
        dict: Category information
    """
    return OWASP_TOP_10_2021.get(category_id)


def get_remediation_for_category(category_id: str) -> str:
    """
    Get remediation guidance for an OWASP category
    
    Args:
        category_id: OWASP category ID
    
    Returns:
        str: Remediation guidance
    """
    info = get_owasp_info(category_id)
    return info['remediation'] if info else "Apply security best practices"


def get_all_categories() -> Dict[str, Dict]:
    """Get all OWASP Top 10 2021 categories"""
    return OWASP_TOP_10_2021


def categorize_vulnerabilities(vulnerabilities: List[Dict]) -> Dict[str, List[Dict]]:
    """
    Group vulnerabilities by OWASP category
    
    Args:
        vulnerabilities: List of vulnerabilities
    
    Returns:
        dict: Vulnerabilities grouped by OWASP category
    """
    categorized = {}
    
    for vuln in vulnerabilities:
        category = vuln.get('owasp_category', 'A05:2021')
        if category not in categorized:
            categorized[category] = []
        categorized[category].append(vuln)
    
    return categorized
