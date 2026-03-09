"""GitLeaks TOML cache — fetch, store, fallback."""

from __future__ import annotations

import logging
import time
import tomllib
from pathlib import Path

from kloak.config import GITLEAKS_CACHE_PATH, GITLEAKS_URL, SECRETS_REFRESH_HOURS

logger = logging.getLogger("kloak")


def _fetch_toml(url: str) -> str:
    """Fetch GitLeaks TOML from URL."""
    import httpx

    response = httpx.get(url, timeout=30, follow_redirects=True)
    response.raise_for_status()
    return response.text


def _is_cache_fresh(cache_path: Path, refresh_hours: int) -> bool:
    if not cache_path.exists():
        return False
    age_hours = (time.time() - cache_path.stat().st_mtime) / 3600
    return age_hours < refresh_hours


def _parse_toml(raw: str, source: str) -> dict:
    try:
        return tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Invalid TOML from {source}: {exc}") from exc


def get_toml(
    *,
    cache_path: Path = GITLEAKS_CACHE_PATH,
    refresh_hours: int = SECRETS_REFRESH_HOURS,
    url: str = GITLEAKS_URL,
) -> dict:
    """Get GitLeaks TOML config. Cache-first with resilient fallback.

    1. Cache fresh → use cached
    2. Cache stale/missing → fetch from URL → write cache
    3. Fetch fails + stale cache → use stale (log warning)
    4. Fetch fails + no cache → return empty (log error)
    """
    # Fresh cache — use it
    if _is_cache_fresh(cache_path, refresh_hours):
        try:
            return _parse_toml(cache_path.read_text(), str(cache_path))
        except ValueError as exc:
            logger.warning("Cache parse failed (%s), refreshing from source.", exc)

    # Try to fetch
    try:
        raw = _fetch_toml(url)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(raw)
        return _parse_toml(raw, url)
    except Exception as e:
        if cache_path.exists():
            logger.warning("Failed to refresh GitLeaks rules (%s). Using stale cache.", e)
            try:
                return _parse_toml(cache_path.read_text(), str(cache_path))
            except ValueError as exc:
                logger.error("Stale cache parse failed: %s", exc)
                return {"rules": []}
        else:
            logger.error("Failed to fetch GitLeaks rules and no cache exists: %s", e)
            return {"rules": []}
