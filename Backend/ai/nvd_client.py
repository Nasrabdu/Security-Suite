import time
import requests

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 10
RATE_LIMIT_DELAY = 2

_cache: dict[str, list[dict]] = {}


def _get_severity(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "NONE"


def _parse_cve_item(item: dict) -> dict:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")

    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"), ""
    )

    published_date = cve.get("published", "")

    # Extract CVSS score — prefer v3.1, fall back to v3.0, then v2
    metrics = cve.get("metrics", {})
    cvss_score = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            break

    # Affected software from CPE matches
    affected_software = []
    configurations = cve.get("configurations", [])
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable"):
                    criteria = cpe_match.get("criteria", "")
                    if criteria:
                        affected_software.append(criteria)

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "severity": _get_severity(cvss_score),
        "published_date": published_date,
        "affected_software": affected_software,
    }


def search_cve(service_name: str, version: str = "") -> list[dict]:
    keyword = f"{service_name} {version}".strip()
    cache_key = keyword.lower()

    if cache_key in _cache:
        return _cache[cache_key]

    params = {"keywordSearch": keyword}
    try:
        time.sleep(RATE_LIMIT_DELAY)
        response = requests.get(NVD_BASE_URL, params=params, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError):
        return []

    vulnerabilities = data.get("vulnerabilities", [])
    results = [_parse_cve_item(item) for item in vulnerabilities]

    _cache[cache_key] = results
    return results


def get_cve_by_id(cve_id: str) -> dict | None:
    cache_key = cve_id.upper()

    if cache_key in _cache:
        cached = _cache[cache_key]
        return cached[0] if cached else None

    params = {"cveId": cve_id}
    try:
        time.sleep(RATE_LIMIT_DELAY)
        response = requests.get(NVD_BASE_URL, params=params, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError):
        return None

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        _cache[cache_key] = []
        return None

    result = _parse_cve_item(vulnerabilities[0])
    _cache[cache_key] = [result]
    return result
