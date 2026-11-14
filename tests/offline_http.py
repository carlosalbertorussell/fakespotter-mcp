"""
Offline HTTP for the tools: every ``httpx.AsyncClient`` they create is given an
``httpx.MockTransport`` that serves registered fixture bytes. URLs that were
not registered behave like an unreachable host (``httpx.ConnectError``), so a
test can never reach the real network by accident.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator
from unittest.mock import patch

import httpx


class FakeWeb:
    """URL -> (bytes, response headers) registry."""

    def __init__(self) -> None:
        self._routes: dict[str, tuple[bytes, dict[str, str]]] = {}
        self.requested: list[str] = []

    def serve(self, url: str, body: bytes, content_type: str = "application/octet-stream",
              headers: dict[str, str] | None = None) -> str:
        self._routes[url] = (body, {"content-type": content_type, **(headers or {})})
        return url

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.requested.append(url)
        if url not in self._routes:
            raise httpx.ConnectError(f"offline test: {url} is not served", request=request)
        body, headers = self._routes[url]
        return httpx.Response(200, content=body, headers=headers)


@contextmanager
def offline_http(fake: FakeWeb | None = None) -> Iterator[FakeWeb]:
    fake = fake or FakeWeb()
    real_client = httpx.AsyncClient

    class _OfflineAsyncClient(real_client):  # type: ignore[misc, valid-type]
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(fake.handler)
            super().__init__(*args, **kwargs)

    with patch.object(httpx, "AsyncClient", _OfflineAsyncClient):
        yield fake
