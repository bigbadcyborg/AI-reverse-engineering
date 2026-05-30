"""
Version identifiers for analysis provenance and reproducibility.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

PROMPT_DIR = Path(__file__).parent.parent / "prompts"

# Bump when post-processing rules change materially.
POSTPROCESS_VERSION = "1.1.0"


def prompt_version_for(template_name: str) -> str:
    """Short content hash of a prompt template file."""
    path = PROMPT_DIR / template_name
    if not path.is_file():
        return "unknown"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest[:12]
