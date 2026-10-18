"""Small VirusTotal API v3 client used by the TUI."""

import re
import time
from typing import Any

import requests


class VirusTotalError(Exception):
    """An API, network, or input error that can be shown to the user."""


class HashNotFound(VirusTotalError):
    """VirusTotal has no report for the requested file hash."""


class VirusTotal:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, timeout: int = 20):
        if not api_key:
            raise VirusTotalError(
                "API key is missing. Set the VT_API_KEY environment variable."
            )
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key, "accept": "application/json"})
        self.timeout = timeout

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = self.session.request(
                method, f"{self.BASE_URL}{path}", timeout=self.timeout, **kwargs
            )
        except requests.RequestException as exc:
            raise VirusTotalError(f"Network error: {exc}") from exc

        if response.status_code == 404:
            raise HashNotFound("No report was found in VirusTotal.")
        if response.status_code == 429:
            raise VirusTotalError(
                "VirusTotal request limit exceeded (HTTP 429). Try again later."
            )
        if response.status_code in (401, 403):
            raise VirusTotalError(
                "VirusTotal rejected the API key or request (HTTP %s)."
                % response.status_code
            )
        if not response.ok:
            detail = ""
            try:
                detail = response.json().get("error", {}).get("message", "")
            except (ValueError, AttributeError):
                pass
            suffix = f": {detail}" if detail else ""
            raise VirusTotalError(
                f"VirusTotal error (HTTP {response.status_code}){suffix}"
            )
        try:
            return response.json()
        except ValueError as exc:
            raise VirusTotalError("VirusTotal returned invalid JSON.") from exc

    def scan_hash(self, sha256: str) -> dict[str, Any]:
        sha256 = sha256.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise VirusTotalError(
                "Enter a valid SHA-256 hash (64 hexadecimal characters)."
            )
        return self._request("GET", f"/files/{sha256}")

    def scan_url(self, url: str, wait_seconds: int = 60) -> dict[str, Any]:
        url = url.strip()
        if not re.match(r"^https?://\S+$", url, re.IGNORECASE):
            raise VirusTotalError("Enter a URL starting with http:// or https://.")
        submission = self._request("POST", "/urls", data={"url": url})
        analysis_id = submission.get("data", {}).get("id")
        if not analysis_id:
            raise VirusTotalError("Could not get the URL analysis ID.")

        deadline = time.monotonic() + wait_seconds
        while True:
            report = self._request("GET", f"/analyses/{analysis_id}")
            attributes = report.get("data", {}).get("attributes", {})
            if attributes.get("status") == "completed":
                url_id = submission.get("meta", {}).get("url_info", {}).get("id")
                if url_id:
                    try:
                        return self._request("GET", f"/urls/{url_id}")
                    except VirusTotalError:
                        pass
                # Analysis statistics remain useful if the URL report is not yet available.
                return {
                    "data": {
                        "attributes": {
                            "last_analysis_stats": attributes.get("stats", {})
                        }
                    }
                }
            if time.monotonic() >= deadline:
                raise VirusTotalError(
                    "The analysis is still running. Try checking the URL again later."
                )
            time.sleep(min(5, max(1, deadline - time.monotonic())))


def extract_stats(report: dict[str, Any]) -> dict[str, int]:
    attributes = report.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats") or attributes.get("stats") or {}
    return {
        name: int(stats.get(name, 0) or 0)
        for name in ("malicious", "suspicious", "harmless", "undetected")
    }
