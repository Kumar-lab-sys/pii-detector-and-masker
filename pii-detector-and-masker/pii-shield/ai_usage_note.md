# AI Usage Note

## What AI Helped With

1. **Column-level PII detection** – Claude Sonnet scans 5 sample rows
   and flags columns that contain implicit PII (e.g., names, free-text
   notes with embedded phone numbers) that regex patterns alone cannot
   reliably catch.

2. **Audit report generation** – Claude writes a professional Markdown
   audit report from structured findings data, including executive
   summary, risk table, observations, recommendations, and compliance
   references (DPDP Act 2023, GDPR).

3. **Prompt design** – AI was used iteratively to improve the prompts
   in `prompts.md` for structured JSON output reliability.

## What AI Got Wrong / Limitations

- **Aadhaar false positives**: LLM occasionally flagged any 12-digit
  numeric sequence as Aadhaar, even order IDs. Regex with boundary
  checks reduces this.
- **JSON output format**: Despite instructions, the LLM sometimes wraps
  output in markdown code fences (`\`\`\`json`). The code strips these
  defensively.
- **PAN vs random uppercase strings**: The LLM sometimes flags
  5-letter + 4-digit + 1-letter patterns in product codes. Human review
  of flagged columns is recommended.
- **Free-text names**: The LLM flags "name" columns correctly but
  masking names is ambiguous — not implemented in regex layer to avoid
  false positives on city or product names.

## Best Prompts Used

See `prompts.md` for the full prompts and lessons learned.

## AI Tools Used

| Tool | Purpose |
|---|---|
| Claude Sonnet (via Anthropic API) | PII column detection + audit report generation |
| Python `re` module | Fast, deterministic regex-based PII matching |
| Streamlit | UI scaffolding |
