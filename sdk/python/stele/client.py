"""Minimal HTTP client for stele.

Uses only stdlib (``urllib.request``) to keep the SDK's dependency
footprint to just ``cryptography``. Operators on bandwidth-or-supply-
chain-constrained networks can audit the wire payload trivially.
"""

from __future__ import annotations

import json
import ssl
from base64 import b64decode, b64encode
from typing import Any, Optional
from urllib import error as urllib_error
from urllib import request as urllib_request


class HTTPError(RuntimeError):
    """Raised when the stele HTTP API returns a non-2xx response."""

    def __init__(self, status: int, body: str):
        super().__init__(f"HTTP {status}: {body[:1024]}")
        self.status = status
        self.body = body


class SteleClient:
    """A small JSON-over-HTTP client.

    ``base_url`` is the operator's URL (e.g. ``https://stele.example.com``).
    ``timeout`` is per request (default 15s).

    Set ``ssl_context`` to a custom :class:`ssl.SSLContext` if the
    operator's TLS cert chains to a private CA — pass a context that
    trusts that CA. Production setups should NOT set
    ``verify=False``; the constructor refuses that for a reason.
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 15.0,
        ssl_context: Optional[ssl.SSLContext] = None,
        extra_headers: Optional[dict] = None,
    ) -> None:
        if not base_url:
            raise ValueError("SteleClient: base_url required")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.ssl_context = ssl_context
        self.extra_headers = dict(extra_headers or {})

    def get(self, path: str) -> Any:
        return self._call("GET", path, None)

    def post(self, path: str, body: Any) -> Any:
        return self._call("POST", path, body)

    def _call(self, method: str, path: str, body: Optional[Any]) -> Any:
        url = self.base_url + path
        data: Optional[bytes] = None
        headers = {"Accept": "application/json", **self.extra_headers}
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib_request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib_request.urlopen(
                req, timeout=self.timeout, context=self.ssl_context
            ) as resp:
                return _decode_json(resp.read())
        except urllib_error.HTTPError as e:
            body_text = ""
            try:
                body_text = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            raise HTTPError(e.code, body_text) from None
        except urllib_error.URLError as e:
            raise HTTPError(0, str(e)) from None


def _decode_json(b: bytes) -> Any:
    if not b:
        return None
    return json.loads(b.decode("utf-8"))


# Convenience helpers for the base64 fields used in the API.
def b64encode_bytes(b: bytes) -> str:
    return b64encode(b).decode("ascii")


def b64decode_str(s: str) -> bytes:
    return b64decode(s)
