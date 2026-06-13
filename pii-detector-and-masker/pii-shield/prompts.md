# Prompts Used in PII Shield

## 1. LLM Column Scanner (`llm_scan_sample`)

**System prompt:**
```
You are a data-privacy auditor.
Identify all columns that contain Personally Identifiable Information (PII).
Focus on: names, emails, phone numbers, PAN numbers, Aadhaar numbers,
addresses, dates-of-birth, and any free-text that embeds such values.
Return ONLY a JSON object like:
{"column_name": ["PII_TYPE1", "PII_TYPE2"], ...}.
No extra text, no markdown fences.
```

**User prompt:**
```
Below are sample rows from a dataset.
List which columns contain PII and what types.

{json.dumps(sample_rows, indent=2)}
```

**What this does:** Asks Claude to review 5 sample rows and flag columns
that contain PII the regex may not catch (e.g., a "notes" column where
someone typed a phone number in words, or a "name" column).

---

## 2. Audit Report Generator (`llm_generate_report`)

**System prompt:**
```
You are a senior data-privacy consultant.
Write a clear, professional PII audit report in Markdown.
Use headings, bullet points, and a risk-level table.
Be specific about findings and give actionable recommendations.
```

**User prompt:**
```
Write a PII Audit Report for the file: {filename}

Dataset statistics:
- Total rows: {total_rows}
- PII types found: {pii_type_counts}

Column-level risk summary: {column_summary}

Sample findings (first 10): {sample_findings}

Include:
1. Executive Summary
2. Findings Table (column, PII types, risk level, exposure %)
3. Detailed observations per PII type
4. Recommended remediation steps
5. Compliance note (reference DPDP Act 2023 and GDPR where relevant)
```

**What this does:** Generates a full Markdown audit report that a
privacy officer can act on immediately.

---

## Best Prompts (Lessons Learned)

| What worked well | What didn't |
|---|---|
| Asking LLM to return **only JSON**, no markdown | LLM sometimes adds ```json fences → strip with regex |
| Giving column names + sample values (not just column names) | Column names alone are often ambiguous |
| Specifying exact output schema in the system prompt | Open-ended output → harder to parse |
| Asking for compliance references (DPDP, GDPR) | LLM sometimes cites wrong act versions → verify manually |
