"""Shared HTTP helpers: a session with retries and a simple rate limiter."""

from __future__ import annotations

import logging
import time
from collections import deque

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# Identify the client politely; some feeds (e.g. CISA) expect this header.
DEFAULT_HEADERS = {
    "User-Agent": "cyber-kris-collector/0.1 (+https://github.com/)",
    "X-Requested-With": "cyber-kris-collector",
}


def build_session(
    total_retries: int = 5,
    backoff_factor: float = 1.0,
    timeout: float = 60.0,
) -> requests.Session:
    """Create a requests Session with sane retry/backoff defaults.

    Retries cover transient network errors and common throttling / server
    status codes (429, 500, 502, 503, 504).
    """
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    retry = Retry(
        total=total_retries,
        connect=total_retries,
        read=total_retries,
        status=total_retries,
        backoff_factor=backoff_factor,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    # Attach a default timeout via a wrapper so callers don't have to repeat it.
    session.request = _with_default_timeout(session.request, timeout)  # type: ignore[method-assign]
    return session


def _with_default_timeout(request_func, timeout: float):
    def wrapped(method, url, **kwargs):
        kwargs.setdefault("timeout", timeout)
        return request_func(method, url, **kwargs)

    return wrapped


class RateLimiter:
    """Sliding-window rate limiter.

    Allows at most ``max_calls`` within any ``period`` seconds. ``wait()``
    blocks until the next call is allowed.
    """

    def __init__(self, max_calls: int, period: float) -> None:
        self.max_calls = max(1, max_calls)
        self.period = period
        self._calls: deque[float] = deque()

    def wait(self) -> None:
        now = time.monotonic()
        # Drop timestamps outside the current window.
        while self._calls and now - self._calls[0] >= self.period:
            self._calls.popleft()

        if len(self._calls) >= self.max_calls:
            sleep_for = self.period - (now - self._calls[0])
            if sleep_for > 0:
                logger.debug("Rate limit reached, sleeping %.2fs", sleep_for)
                time.sleep(sleep_for)
            # Refresh window after sleeping.
            now = time.monotonic()
            while self._calls and now - self._calls[0] >= self.period:
                self._calls.popleft()

        self._calls.append(time.monotonic())
