# 🛡️ PII Shield – AI-Powered PII Detector & Masker

**Team Project | AI Prototype Challenge**

> Datasets accidentally contain PII. PII Shield reads a CSV or JSON file, uses a hybrid Regex + LLM agent to detect emails, phone numbers, PAN numbers, and Aadhaar numbers, produces a masked copy of the dataset, and generates a professional audit report.

---

## 👥 Team Members

| Name | Role |
|------|------|
| Student 1 | Streamlit UI & app flow |
| Student 2 | Python backend, regex engine, data processing |
| Student 3 | LLM prompts, AI integration, structured output |
| Student 4 | README, tests, AI usage note, demo video |

---

## ✨ Features

- **Hybrid PII detection** – Regex catches structured PII (email, phone, PAN, Aadhaar); LLM catches implicit PII in free-text columns
- **Auto-masking** – Replaces PII with format-preserving masks (e.g. `ar****.sh***@gmail.com`, `XXXX XXXX 9012`)
- **Column risk summary** – Flags HIGH / MEDIUM / LOW risk per column with exposure %
- **Downloadable masked CSV** – Clean, safe dataset ready for sharing
- **AI-generated audit report** – Markdown report with findings table, observations, and DPDP Act 2023 / GDPR compliance notes
- **Supports CSV and JSON** input files

---

## 🏗️ Architecture Overview

```
User uploads CSV/JSON
        │
        ▼
┌──────────────────────┐
│  processor.py        │  ← Regex engine (EMAIL, PHONE_IN, PAN, AADHAAR)
│  scan_dataframe()    │  ← Scans every cell, returns findings + masked df
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  llm_helper.py       │  ← Anthropic Claude API
│  llm_scan_sample()   │  ← Column-level PII flags from LLM
│  llm_generate_report │  ← Markdown audit report
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  app.py (Streamlit)  │  ← Results UI: findings table, masked data,
│                      │     risk chart, report, download buttons
└──────────────────────┘
           │
           ▼
   outputs/ folder
   masked_<ts>.csv
   findings_<ts>.csv
   audit_report_<ts>.md
```

---

## 🛠️ Tools & Technologies

| Layer | Tool |
|---|---|
| Language | Python 3.10+ |
| UI | Streamlit |
| AI Model | Claude Sonnet (Anthropic API) |
| PII Detection | Python `re` (regex) + LLM |
| Data Handling | Pandas |
| HTTP Client | Requests |
| Testing | Pytest |
| Version Control | GitHub |

---

## ⚙️ Setup Instructions

### Prerequisites
- Python 3.10 or higher
- An [Anthropic API key](https://console.anthropic.com/) (free tier works)

### Install

```bash
git clone https://github.com/<your-team>/pii-shield.git
cd pii-shield
pip install -r requirements.txt
```

---

## ▶️ Run Instructions

```bash
streamlit run app.py
```

1. Open `http://localhost:8501` in your browser.
2. Enter your **Anthropic API key** in the sidebar (or set `ANTHROPIC_API_KEY` env var).
3. Upload a CSV or JSON file (or load the sample data).
4. Click **🔍 Scan for PII**.
5. Review findings, download the masked CSV, and download the audit report.

### Run without API key (regex-only mode)
The app works without an API key — LLM scanning and report generation are skipped, but all regex detection and masking still work.

### Run tests

```bash
pytest tests/test_basic.py -v
```

---

## 📂 Sample Input & Output

| File | Description |
|---|---|
| `data/sample_input.csv` | 8-row dataset with emails, phones, PAN, Aadhaar |
| `data/sample_input.json` | 3-record JSON with similar PII fields |
| `outputs/sample_output.csv` | Masked version of the CSV |
| `outputs/final_report.md` | Sample audit report |

---

## 🤖 AI Capability Demonstrated

| Capability | Implementation |
|---|---|
| **Agent Loop** | App reads input → regex scans → LLM validates columns → LLM generates report → saves output files |
| **Hybrid Detector** | Regex for structured PII + LLM for free-text / implicit PII |
| **LLM Structured Output** | `llm_scan_sample()` returns strict JSON `{column: [pii_types]}` |
| **External API** | Anthropic Messages API (`/v1/messages`) |

---

## ⚠️ Assumptions & Limitations

- Phone detection targets **Indian mobile numbers** (starts with 6–9, 10 digits). International formats may be missed.
- Aadhaar regex may produce false positives on 12-digit numeric strings (e.g., order IDs). Treat as advisory.
- LLM scanning uses the **first 5 rows** as a sample — columns with PII only in later rows may be missed by the LLM step (regex still catches them).
- Names are not masked by default (too many false positives on place names and product names).
- The app requires internet access to call the Anthropic API.

---

## 🎥 Demo Video

> [Insert your 5–7 minute demo video link here]

---

## 📜 Compliance References

- [Digital Personal Data Protection Act 2023 (India)](https://meity.gov.in/writereaddata/files/Digital%20Personal%20Data%20Protection%20Act%202023.pdf)
- [GDPR – European Data Protection](https://gdpr.eu/)
