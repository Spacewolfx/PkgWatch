"""Retry policy: only 429, 5xx and timeouts; capped attempts; Retry-After honoured."""

from __future__ import annotations

import pytest

from pkgwatch.fetch.npm import FetchTimeout, HttpResponse
from pkgwatch.fetch.retry import RetryingClient, RetryPolicy


class _ScriptedClient:
    """Returns one scripted item per call; an exception item is raised."""

    def __init__(self, *items: HttpResponse | Exception) -> None:
        self._items = list(items)
        self.requests: list[str] = []

    def get(self, url: str, *, user_agent: str, timeout: float, max_bytes: int) -> HttpResponse:
        self.requests.append(url)
        item = self._items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _policy(sleep: list[float], **overrides: object) -> RetryPolicy:
    values: dict[str, object] = {
        "max_attempts": 3,
        "base_delay": 0.5,
        "max_delay": 8.0,
        "request_delay": 0.0,
        "sleep": sleep.append,
    }
    values.update(overrides)
    return RetryPolicy(**values)  # type: ignore[arg-type]


def _ok() -> HttpResponse:
    return HttpResponse(status=200, headers={}, body=b"ok")


def _retry(status: int, **headers: str) -> HttpResponse:
    return HttpResponse(status=status, headers=headers, body=b"")


def _get(client: RetryingClient) -> HttpResponse:
    return client.get("https://registry.npmjs.org/x", user_agent="ua", timeout=1.0, max_bytes=10)


def test_a_429_is_retried_and_the_following_success_is_returned() -> None:
    sleeps: list[float] = []
    inner = _ScriptedClient(_retry(429), _ok())
    client = RetryingClient(inner, policy=_policy(sleeps))

    response = _get(client)

    assert response.status == 200
    assert len(inner.requests) == 2
    assert sleeps == [0.5]


def test_retry_after_is_honoured_over_the_default_backoff() -> None:
    sleeps: list[float] = []
    inner = _ScriptedClient(_retry(429, **{"Retry-After": "2"}), _ok())
    client = RetryingClient(inner, policy=_policy(sleeps))

    assert _get(client).status == 200
    assert sleeps == [2.0]


def test_backoff_doubles_and_is_capped() -> None:
    sleeps: list[float] = []
    inner = _ScriptedClient(_retry(503), _retry(500), _ok())
    client = RetryingClient(inner, policy=_policy(sleeps, max_attempts=4))

    assert _get(client).status == 200
    assert sleeps == [0.5, 1.0]


def test_the_attempt_cap_returns_the_last_response() -> None:
    sleeps: list[float] = []
    inner = _ScriptedClient(_retry(429), _retry(429), _retry(429))
    client = RetryingClient(inner, policy=_policy(sleeps))

    response = _get(client)

    assert response.status == 429
    assert len(inner.requests) == 3
    assert sleeps == [0.5, 1.0]


def test_a_timeout_is_retried() -> None:
    sleeps: list[float] = []
    inner = _ScriptedClient(FetchTimeout(), _ok())
    client = RetryingClient(inner, policy=_policy(sleeps))

    assert _get(client).status == 200
    assert len(inner.requests) == 2
    assert sleeps == [0.5]


def test_a_timeout_is_raised_after_the_cap() -> None:
    sleeps: list[float] = []
    inner = _ScriptedClient(FetchTimeout(), FetchTimeout(), FetchTimeout())
    client = RetryingClient(inner, policy=_policy(sleeps))

    with pytest.raises(FetchTimeout):
        _get(client)
    assert len(inner.requests) == 3


def test_a_non_retryable_status_is_returned_immediately() -> None:
    sleeps: list[float] = []
    inner = _ScriptedClient(_retry(404), _ok())
    client = RetryingClient(inner, policy=_policy(sleeps))

    assert _get(client).status == 404
    assert len(inner.requests) == 1
    assert sleeps == []


def test_the_polite_request_delay_applies_to_every_attempt() -> None:
    sleeps: list[float] = []
    inner = _ScriptedClient(_retry(429), _ok())
    client = RetryingClient(inner, policy=_policy(sleeps, request_delay=0.25))

    assert _get(client).status == 200
    assert sleeps == [0.25, 0.5, 0.25]
