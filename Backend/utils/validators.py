"""
utils/validators.py
Target validation and sanitization for scan inputs.
Prevents command injection, SSRF to internal networks, and malformed inputs.
"""

import re
import socket
import ipaddress
from typing import Tuple


# ── Blocked private / loopback ranges ────────────────────────
# Prevent SSRF — scanning the server itself or internal LAN
# Remove entries from this list only if you explicitly want to allow them.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 unique local
]

# Set to True to also block RFC-1918 private ranges (192.168.x, 10.x, 172.16-31.x).
# For a LAN pentest platform you likely WANT to scan these, so it defaults to False.
BLOCK_PRIVATE_RANGES = False

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# ── Allowed characters in a hostname ─────────────────────────
_HOSTNAME_RE = re.compile(
    r'^(?:[a-zA-Z0-9]'
    r'(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
)

# Characters that are dangerous in shell contexts — reject immediately
_SHELL_CHARS_RE = re.compile(r'[;&|`$<>\'"\\\n\r\t\x00]')


def validate_and_normalize_target(raw: str) -> Tuple[bool, str, str]:
    """
    Validate and normalize a scan target (hostname, IP, or URL).

    Returns: (is_valid, normalized_target, error_message)
    """
    if not raw or not raw.strip():
        return False, '', 'Target cannot be empty'

    target = raw.strip()

    # ── Length guard ──────────────────────────────────────────
    if len(target) > 253:
        return False, '', 'Target is too long (max 253 characters)'

    # ── Shell injection guard ─────────────────────────────────
    if _SHELL_CHARS_RE.search(target):
        return False, '', 'Target contains invalid characters'

    # ── Strip URL scheme if present (http:// / https://) ──────
    target = re.sub(r'^https?://', '', target, flags=re.IGNORECASE)

    # ── Strip trailing path/query (keep only host[:port]) ─────
    target = target.split('/')[0].split('?')[0].split('#')[0]

    # ── Strip port suffix for validation ──────────────────────
    host = target.split(':')[0]

    # ── Try as IP address first ───────────────────────────────
    try:
        addr = ipaddress.ip_address(host)
        if not _is_ip_allowed(addr):
            return False, '', f'Scanning {host} is not allowed (reserved/private address)'
        return True, host, ''
    except ValueError:
        pass

    # ── Validate as hostname ──────────────────────────────────
    if not _HOSTNAME_RE.match(host):
        return False, '', f'Invalid hostname format: {host!r}'

    return True, host, ''


def resolve_target(target: str) -> Tuple[bool, str, str]:
    """
    Resolve hostname to IP and verify it is allowed to be scanned.

    Returns: (success, ip_address, error_message)
    """
    try:
        ip_str = socket.gethostbyname(target)
        addr   = ipaddress.ip_address(ip_str)

        if not _is_ip_allowed(addr):
            return False, '', f'Resolved IP {ip_str} is not allowed (reserved/private address)'

        return True, ip_str, ''

    except socket.gaierror as e:
        return False, '', f'DNS resolution failed for {target!r}: {e}'
    except Exception as e:
        return False, '', f'Resolution error: {e}'


def sanitize_scan_type(raw: str, allowed: dict) -> str:
    """
    Return the normalized scan type or 'quick' as a safe default.
    Never passes an arbitrary string to a subprocess.
    """
    cleaned = (raw or '').strip().lower()
    return allowed.get(cleaned, 'quick')


# ── Internal helpers ──────────────────────────────────────────

def _is_ip_allowed(addr: ipaddress._BaseAddress) -> bool:
    """Return True if the IP address is allowed to be scanned."""
    # Always block loopback and link-local
    for net in _BLOCKED_NETWORKS:
        try:
            if addr in net:
                return False
        except TypeError:
            pass  # IPv4 addr vs IPv6 network — skip

    # Optionally block private RFC-1918 ranges
    if BLOCK_PRIVATE_RANGES:
        for net in _PRIVATE_NETWORKS:
            try:
                if addr in net:
                    return False
            except TypeError:
                pass

    return True
