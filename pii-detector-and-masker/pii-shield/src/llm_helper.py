"""
llm_helper.py – Calls the LLM to detect PII that regex may miss
and to generate the final narrative report.
"""

import os
import json
import re
import requests

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-sonnet-4-6"


def _call_llm(prompt: str, system: str = "", max_tokens: int = 1024) -> str:
    """Low-level call to the Anthropic Messages API."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    body: dict = {
        "model": MODEL,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        body["system"] = system

    resp = requests.post(ANTHROPIC_API_URL, headers=headers, json=body, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    return data["content"][0]["text"]


def llm_scan_sample(sample_rows: list[dict]) -> dict:
    """
    Ask the LLM to identify any PII in a sample of rows that regex
    may have missed.  Returns a dict mapping column names to detected
    PII types.
    """
    system = (
        "You are a data-privacy auditor. "
        "Identify all columns that contain Personally Identifiable Information (PII). "
        "Focus on: names, emails, phone numbers, PAN numbers, Aadhaar numbers, "
        "addresses, dates-of-birth, and any free-text that embeds such values. "
        "Return ONLY a JSON object like: "
        '{"column_name": ["PII_TYPE1", "PII_TYPE2"], ...}. '
        "No extra text, no markdown fences."
    )
    prompt = (
        "Below are sample rows from a dataset. "
        "List which columns contain PII and what types.\n\n"
        f"{json.dumps(sample_rows, indent=2, default=str)}"
    )
    raw = _call_llm(prompt, system=system, max_tokens=512)
    # Strip possible markdown fences just in case
    raw = re.sub(r"```json|```", "", raw).strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


def llm_generate_report(
    filename: str,
    total_rows: int,
    column_summary: list[dict],
    pii_type_counts: dict,
    sample_findings: list[dict],
) -> str:
    """
    Ask the LLM to write a professional PII audit report in Markdown.
    """
    system = (
        "You are a senior data-privacy consultant. "
        "Write a clear, professional PII audit report in Markdown. "
        "Use headings, bullet points, and a risk-level table. "
        "Be specific about findings and give actionable recommendations."
    )
    prompt = f"""
Write a PII Audit Report for the file: **{filename}**

Dataset statistics:
- Total rows: {total_rows}
- PII types found: {json.dumps(pii_type_counts, indent=2)}

Column-level risk summary:
{json.dumps(column_summary, indent=2)}

Sample findings (first 10):
{json.dumps(sample_findings[:10], indent=2, default=str)}

Include:
1. Executive Summary
2. Findings Table (column, PII types, risk level, exposure %)
3. Detailed observations per PII type
4. Recommended remediation steps
5. Compliance note (reference DPDP Act 2023 and GDPR where relevant)
"""
    return _call_llm(prompt, system=system, max_tokens=1500)
