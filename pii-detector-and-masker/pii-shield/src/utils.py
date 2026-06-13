"""
utils.py – Shared utility functions.
"""

import os
import json
from datetime import datetime


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def save_json(data: dict | list, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def format_pii_badge(pii_type: str) -> str:
    color_map = {
        "EMAIL": "🟡",
        "PHONE_IN": "🟠",
        "PAN": "🔴",
        "AADHAAR": "🔴",
    }
    return f"{color_map.get(pii_type, '⚪')} {pii_type}"
