import json
import sqlite3
import time
from typing import List, Optional

import requests

from utils.common import print_status
from utils.config import CVEConfig
from utils.models import CVEMatch

NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def severity_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


class CVECache:
    """Local sqlite cache of raw NVD lookup results, keyed by CPE or keyword
    query string, so repeated runs against the same service/version don't
    re-hit the NVD API (and its tight rate limits) every time."""

    def __init__(self, db_path: str, ttl_days: int = 30):
        self.db_path = db_path
        self.ttl_seconds = ttl_days * 86400
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS cve_cache ("
                "key TEXT PRIMARY KEY, payload TEXT NOT NULL, cached_at REAL NOT NULL)"
            )

    def get(self, key: str) -> Optional[list]:
        with self._connect() as conn:
            row = conn.execute("SELECT payload, cached_at FROM cve_cache WHERE key = ?", (key,)).fetchone()
        if not row:
            return None
        payload, cached_at = row
        if time.time() - cached_at > self.ttl_seconds:
            return None
        return json.loads(payload)

    def put(self, key: str, matches: list):
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO cve_cache (key, payload, cached_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET payload = excluded.payload, cached_at = excluded.cached_at",
                (key, json.dumps(matches), time.time()),
            )


class CVELookupClient:
    """Deterministic, provider-neutral vulnerability matching against the NVD
    CVE API 2.0. Prefers CPE-based lookup (matches nmap's own cpe: output)
    for precision; falls back to a lower-confidence keyword search. Runs
    sequentially after the scan completes, never inside the scan thread pool,
    to keep rate-limit bookkeeping simple and centralized."""

    def __init__(self, config: CVEConfig, cache: CVECache):
        self.config = config
        self.cache = cache
        self._last_call = 0.0

    def lookup(self, port_result) -> List[CVEMatch]:
        if self.config.source == "off":
            return []
        if port_result.cpe:
            return self._lookup_by_cpe(port_result.cpe)
        if port_result.service and port_result.version:
            return self._lookup_by_keyword(port_result.service, port_result.version)
        return []

    def _lookup_by_cpe(self, cpe: str) -> List[CVEMatch]:
        cache_key = f"cpe:{cpe}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return [self._to_match(entry, cpe) for entry in cached]

        raw = self._query({"cpeName": cpe})
        self.cache.put(cache_key, raw)
        return [self._to_match(entry, cpe) for entry in raw]

    def _lookup_by_keyword(self, service: str, version: str) -> List[CVEMatch]:
        keyword = f"{service} {version}".strip()
        cache_key = f"keyword:{keyword.lower()}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return [self._to_match(entry, None) for entry in cached]

        raw = self._query({"keywordSearch": keyword})
        self.cache.put(cache_key, raw)
        return [self._to_match(entry, None) for entry in raw]

    def _query(self, params: dict) -> list:
        self._respect_rate_limit()
        headers = {"apiKey": self.config.nvd_api_key} if self.config.nvd_api_key else {}
        try:
            response = requests.get(NVD_CVE_API_URL, params=params, headers=headers, timeout=self.config.request_timeout)
            if response.status_code != 200:
                print_status(f"[!] NVD lookup returned {response.status_code} for {params}", "warning")
                return []
            data = response.json()
        except requests.RequestException as e:
            print_status(f"[!] NVD lookup failed: {e}", "warning")
            return []
        except ValueError as e:
            print_status(f"[!] NVD lookup returned invalid JSON: {e}", "warning")
            return []

        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            descriptions = cve.get("descriptions", [])
            summary = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
            cvss = self._extract_cvss(cve.get("metrics", {}))
            references = cve.get("references", [])
            reference_url = references[0].get("url") if references else None
            results.append({
                "cve_id": cve_id,
                "summary": summary,
                "cvss": cvss,
                "reference_url": reference_url,
            })
        return results

    @staticmethod
    def _extract_cvss(metrics: dict) -> Optional[float]:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                return entries[0].get("cvssData", {}).get("baseScore")
        return None

    def _to_match(self, entry: dict, matched_cpe: Optional[str]) -> CVEMatch:
        cvss = entry.get("cvss")
        return CVEMatch(
            cve_id=entry["cve_id"],
            summary=entry.get("summary", ""),
            cvss=cvss,
            severity=severity_from_cvss(cvss),
            source="nvd",
            matched_cpe=matched_cpe,
            reference_url=entry.get("reference_url"),
        )

    def _respect_rate_limit(self):
        # NVD: 5 req/30s without an API key, 50 req/30s with one.
        delay = 0.6 if self.config.nvd_api_key else 6.0
        elapsed = time.monotonic() - self._last_call
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_call = time.monotonic()
