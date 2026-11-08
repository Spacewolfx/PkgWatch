"""Retry with capped exponential backoff for the lock command (SPEC §9.1).

Only 429, 5xx and timeouts are retried. ``Retry-After`` is honoured (bounded by
``max_delay``), attempts are capped, and an optional per-request delay keeps the command
polite. A non-retryable status is returned immediately so the caller's stable code
(``HTTP_ERROR``) is unchanged.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from pkgwatch.fetch.npm import FetchTimeout, HttpClient, HttpResponse

RETRYABLE_STATUSES = frozenset({429})


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay: float = 0.5
    max_delay: float = 8.0
    request_delay: float = 0.1
    sleep: Callable[[float], None] = field(default=time.sleep)


class RetryingClient:
    """An ``HttpClient`` that retries only transient failures, never other responses."""

    def __init__(self, inner: HttpClient, *, policy: RetryPolicy) -> None:
        self._inner = inner
        self._policy = policy

    def get(self, url: str, *, user_agent: str, timeout: float, max_bytes: int) -> HttpResponse:
        attempt = 1
        while True:
            if self._policy.request_delay > 0:
                self._policy.sleep(self._policy.request_delay)
            try:
                response = self._inner.get(
                    url, user_agent=user_agent, timeout=timeout, max_bytes=max_bytes
                )
            except FetchTimeout:
                if attempt >= self._policy.max_attempts:
                    raise
                self._policy.sleep(self._backoff(attempt, headers={}))
                attempt += 1
                continue

            if self._is_retryable(response.status) and attempt < self._policy.max_attempts:
                self._policy.sleep(self._backoff(attempt, response.headers))
                attempt += 1
                continue
            return response

    def _is_retryable(self, status: int) -> bool:
        return status in RETRYABLE_STATUSES or 500 <= status <= 599

    def _backoff(self, attempt: int, headers: Mapping[str, str]) -> float:
        delay = min(self._policy.base_delay * (2.0 ** (attempt - 1)), self._policy.max_delay)
        retry_after = _retry_after_seconds(headers)
        if retry_after is not None:
            delay = max(delay, retry_after)
        return min(delay, self._policy.max_delay)


def _retry_after_seconds(headers: Mapping[str, str]) -> float | None:
    raw = next(
        (value for key, value in headers.items() if key.casefold() == "retry-after"),
        None,
    )
    if raw is None:
        return None
    try:
        seconds = float(raw.strip())
    except ValueError:
        return None
    if seconds < 0 or seconds != seconds:  # NaN is not a usable delay
        return None
    return seconds
