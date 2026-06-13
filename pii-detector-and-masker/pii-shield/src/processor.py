"""
processor.py – PII scanning logic using hybrid regex + LLM approach.
"""

import re
import pandas as pd
import json
from typing import Any

# ──────────────────────────────────────────────
# Regex patterns for Indian & common PII types
# ──────────────────────────────────────────────
PATTERNS = {
    "EMAIL": re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE
    ),
    "PHONE_IN": re.compile(
        r"(?<!\d)(\+91[\-\s]?)?[6-9]\d{9}(?!\d)"
    ),
    "PAN": re.compile(
        r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"
    ),
    "AADHAAR": re.compile(
        r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"
    ),
}

MASK_MAP = {
    "EMAIL":    lambda m: re.sub(r"(?<=.{2}).(?=.*@)", "*", m),
    "PHONE_IN": lambda m: m[:2] + "******" + m[-2:],
    "PAN":      lambda m: m[:2] + "*****" + m[-1:],
    "AADHAAR":  lambda m: "XXXX XXXX " + m.replace(" ", "").replace("-", "")[-4:],
}


def detect_regex(text: str) -> list[dict]:
    """Return list of {pii_type, value, start, end} found by regex."""
    hits = []
    for ptype, pattern in PATTERNS.items():
        for m in pattern.finditer(str(text)):
            hits.append(
                {
                    "pii_type": ptype,
                    "value": m.group(),
                    "start": m.start(),
                    "end": m.end(),
                }
            )
    return hits


def mask_text(text: str, detections: list[dict]) -> str:
    """Apply masking to detected PII in a text string."""
    masked = str(text)
    # Process in reverse order to preserve offsets
    for det in sorted(detections, key=lambda x: x["start"], reverse=True):
        ptype = det["pii_type"]
        masker = MASK_MAP.get(ptype, lambda v: "***MASKED***")
        replacement = masker(det["value"])
        masked = masked[: det["start"]] + replacement + masked[det["end"] :]
    return masked


def scan_dataframe(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Scan every cell in the DataFrame.
    Returns (masked_df, findings_df).
    findings_df columns: row, column, pii_type, original_value
    """
    masked_df = df.copy()
    findings = []

    for col in df.columns:
        for idx, cell in df[col].items():
            cell_str = str(cell) if pd.notna(cell) else ""
            hits = detect_regex(cell_str)
            if hits:
                masked_df.at[idx, col] = mask_text(cell_str, hits)
                for h in hits:
                    findings.append(
                        {
                            "row": idx,
                            "column": col,
                            "pii_type": h["pii_type"],
                            "original_value": h["value"],
                        }
                    )

    findings_df = pd.DataFrame(
        findings,
        columns=["row", "column", "pii_type", "original_value"],
    )
    return masked_df, findings_df


def load_file(path: str) -> pd.DataFrame:
    """Load CSV or JSON file into a DataFrame."""
    if path.endswith(".csv"):
        return pd.read_csv(path)
    elif path.endswith(".json"):
        with open(path) as f:
            data = json.load(f)
        return pd.DataFrame(data) if isinstance(data, list) else pd.json_normalize(data)
    else:
        raise ValueError("Unsupported file type. Please upload CSV or JSON.")


def column_risk_summary(findings_df: pd.DataFrame, df: pd.DataFrame) -> list[dict]:
    """Summarise PII risk per column."""
    if findings_df.empty:
        return []
    summary = []
    for col, grp in findings_df.groupby("column"):
        pii_types = grp["pii_type"].unique().tolist()
        count = len(grp)
        total = len(df)
        summary.append(
            {
                "column": col,
                "pii_types_found": ", ".join(pii_types),
                "affected_rows": count,
                "exposure_pct": round(count / total * 100, 1),
                "risk_level": "HIGH" if count > total * 0.5 else "MEDIUM" if count > 2 else "LOW",
            }
        )
    return summary
