"""Central configuration loaded from environment variables / .env file."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    # Load variables from a local .env file if python-dotenv is installed.
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover - dotenv is optional at runtime
    pass


@dataclass(frozen=True)
class Config:
    """Runtime configuration for the collectors."""

    nvd_api_key: str | None
    data_dir: Path
    edgar_user_agent: str | None

    @classmethod
    def load(cls) -> "Config":
        # Accept either NVD_API_KEY (preferred) or NIST_API_KEY as an alias.
        api_key = os.getenv("NVD_API_KEY") or os.getenv("NIST_API_KEY") or None
        data_dir = Path(os.getenv("DATA_DIR", "data")).expanduser()
        # SEC asks for a descriptive contact string in the User-Agent header.
        edgar_ua = os.getenv("EDGAR_USER_AGENT") or None
        return cls(
            nvd_api_key=api_key,
            data_dir=data_dir,
            edgar_user_agent=edgar_ua,
        )

    def ensure_data_dir(self) -> Path:
        """Create the data directory (and parents) if needed, return it."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.data_dir
