"""Minimal NVD CVE API 2.0 client.

Why NVD as the entry point: it is the only free source that lets you ask
"everything published between date A and date B" directly, which is exactly the
"past X months" query. Its reference lists are also where the GitHub patch links
live.

API constraints we have to respect:
  * pubStartDate/pubEndDate must span <= 120 days, so long windows get chunked
  * resultsPerPage <= 2000, paginated with startIndex
  * 5 requests / 30s anonymous, 50 requests / 30s with an API key
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterator

import requests

log = logging.getLogger(__name__)

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_WINDOW_DAYS = 119  # NVD says 120; stay under to avoid off-by-one rejects
PAGE_SIZE = 2000


@dataclass
class NvdCve:
    cve_id: str
    published: str
    last_modified: str
    description: str
    cvss_score: float | None
    cvss_severity: str | None
    cwes: list
    reference_urls: list
    patch_urls: list  # subset of references NVD tagged as "Patch"

    @classmethod
    def from_api(cls, item: dict) -> "NvdCve":
        cve = item["cve"]

        description = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break

        score, severity = _best_cvss(cve.get("metrics", {}))

        cwes = []
        for weakness in cve.get("weaknesses", []):
            for d in weakness.get("description", []):
                value = d.get("value", "")
                if value.startswith("CWE-"):
                    cwes.append(value)

        refs = cve.get("references", [])
        return cls(
            cve_id=cve["id"],
            published=cve.get("published", ""),
            last_modified=cve.get("lastModified", ""),
            description=description,
            cvss_score=score,
            cvss_severity=severity,
            cwes=sorted(set(cwes)),
            reference_urls=[r["url"] for r in refs if "url" in r],
            patch_urls=[
                r["url"] for r in refs if "Patch" in (r.get("tags") or [])
            ],
        )

    def to_json(self) -> dict:
        return self.__dict__.copy()


def _best_cvss(metrics: dict) -> tuple:
    """Prefer v3.1 > v3.0 > v2, and the Primary source within each."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entries = sorted(entries, key=lambda e: e.get("type") != "Primary")
        data = entries[0].get("cvssData", {})
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
        return score, severity
    return None, None


class NvdClient:
    def __init__(self, api_key: str | None = None, timeout: int = 60):
        self.api_key = api_key or os.environ.get("NVD_API_KEY") or None
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "commit-labels/0.1 (research)"
        if self.api_key:
            self.session.headers["apiKey"] = self.api_key
        # NVD's documented courtesy delay between requests.
        self.delay = 0.7 if self.api_key else 6.5
        self._last_request = 0.0

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_request = time.monotonic()

    def _get(self, params: dict, max_retries: int = 5) -> dict:
        for attempt in range(max_retries):
            self._throttle()
            try:
                resp = self.session.get(
                    API_URL, params=params, timeout=self.timeout
                )
            except requests.RequestException as exc:
                wait = 2 ** attempt
                log.warning("NVD request failed (%s), retrying in %ss", exc, wait)
                time.sleep(wait)
                continue

            if resp.status_code == 200:
                return resp.json()
            # NVD returns 403 for rate limiting, not 429.
            if resp.status_code in (403, 429, 500, 503):
                wait = min(60, 2 ** attempt * 5)
                log.warning(
                    "NVD returned %s, backing off %ss", resp.status_code, wait
                )
                time.sleep(wait)
                continue
            resp.raise_for_status()
        raise RuntimeError(f"NVD request failed after {max_retries} attempts")

    def iter_cves_published_between(
        self, start: datetime, end: datetime
    ) -> Iterator[NvdCve]:
        """Yield every CVE published in [start, end), chunking the window."""
        for chunk_start, chunk_end in _split_window(start, end):
            log.info(
                "NVD window %s .. %s",
                chunk_start.date(),
                chunk_end.date(),
            )
            start_index = 0
            while True:
                params = {
                    "pubStartDate": _fmt(chunk_start),
                    "pubEndDate": _fmt(chunk_end),
                    "resultsPerPage": PAGE_SIZE,
                    "startIndex": start_index,
                }
                payload = self._get(params)
                items = payload.get("vulnerabilities", [])
                for item in items:
                    yield NvdCve.from_api(item)

                total = payload.get("totalResults", 0)
                start_index += payload.get("resultsPerPage", len(items))
                log.debug("  %d/%d", min(start_index, total), total)
                if start_index >= total or not items:
                    break


def _fmt(dt: datetime) -> str:
    # NVD wants ISO-8601 with milliseconds and no timezone suffix issues.
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def _split_window(start: datetime, end: datetime) -> Iterator[tuple]:
    cursor = start
    while cursor < end:
        chunk_end = min(cursor + timedelta(days=MAX_WINDOW_DAYS), end)
        yield cursor, chunk_end
        cursor = chunk_end


def months_ago(months: int, now: datetime | None = None) -> datetime:
    """Approximate calendar months back from now (UTC)."""
    now = now or datetime.now(timezone.utc)
    year = now.year
    month = now.month - months
    while month <= 0:
        month += 12
        year -= 1
    day = min(now.day, _days_in_month(year, month))
    return now.replace(year=year, month=month, day=day)


def _days_in_month(year: int, month: int) -> int:
    import calendar

    return calendar.monthrange(year, month)[1]
