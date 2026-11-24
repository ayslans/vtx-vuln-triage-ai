from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Optional


class FileCache:
    """Cache simples em disco baseado em JSON com expiração por TTL (em segundos)."""

    def __init__(self, cache_dir: str | Path = "data/cache", default_ttl_seconds: int = 86400) -> None:
        self.cache_dir = Path(cache_dir)
        self.default_ttl_seconds = default_ttl_seconds
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, key: str) -> Path:
        safe_key = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in key)
        return self.cache_dir / f"{safe_key}.json"

    def get(self, key: str, ttl_seconds: Optional[int] = None) -> Optional[Any]:
        path = self._path_for(key)
        if not path.exists():
            return None

        try:
            with path.open("r", encoding="utf-8") as file:
                envelope = json.load(file)
        except (OSError, json.JSONDecodeError):
            return None

        saved_at = envelope.get("saved_at", 0)
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        if (time.time() - saved_at) > ttl:
            return None

        return envelope.get("payload")

    def set(self, key: str, payload: Any) -> None:
        path = self._path_for(key)
        envelope = {
            "saved_at": time.time(),
            "payload": payload,
        }
        with path.open("w", encoding="utf-8") as file:
            json.dump(envelope, file, ensure_ascii=False)
