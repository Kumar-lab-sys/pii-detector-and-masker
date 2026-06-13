"""
app.py – PII Shield: Hybrid Regex + LLM PII Detector & Masker
Run: streamlit run app.py
"""

import os
import io
import json
import tempfile
import pandas as pd
import streamlit as st

# Add src to path
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from processor import load_file, scan_dataframe, column_risk_summary
from llm_helper import llm_scan_sample, llm_generate_report
from utils import timestamp, format_pii_badge

# ──────────────────────────────────────────────
# Page config
# ──────────────────────────────────────────────
st.set_page_config(
    page_title="PII Shield",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ PII Shield – AI-Powered PII Detector & Masker")
st.caption(
    "Upload a CSV or JSON dataset. The agent scans columns & values using "
    "**hybrid regex + LLM detection**, masks all PII, and produces a detailed audit report."
)

# ──────────────────────────────────────────────
# Sidebar – API key
# ──────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Configuration")
    api_key = st.text_input(
        "Anthropic API Key",
        type="password",
        value=os.environ.get("ANTHROPIC_API_KEY", ""),
        help="Required for LLM-powered scanning and report generation.",
    )
    if api_key:
        os.environ["ANTHROPIC_API_KEY"] = api_key

    st.markdown("---")
    st.markdown("**PII Types Detected**")
    st.markdown("🟡 Email addresses")
    st.markdown("🟠 Indian phone numbers")
    st.markdown("🔴 PAN numbers")
    st.markdown("🔴 Aadhaar numbers")
    st.markdown("🤖 LLM detects implicit PII in free-text columns")

    st.markdown("---")
    st.markdown("**Tech Stack**")
    st.code("Python · Streamlit · Regex · Claude Sonnet", language="")

# ──────────────────────────────────────────────
# File upload
# ──────────────────────────────────────────────
uploaded = st.file_uploader(
    "Upload your dataset", type=["csv", "json"], label_visibility="collapsed"
)

if not uploaded:
    st.info("👆 Upload a CSV or JSON file to begin scanning.")
    with st.expander("📂 Try with sample data"):
        sample_choice = st.selectbox("Choose sample", ["sample_input.csv", "sample_input.json"])
        if st.button("Load Sample"):
            sample_path = os.path.join(os.path.dirname(__file__), "data", sample_choice)
            if os.path.exists(sample_path):
                with open(sample_path, "rb") as f:
                    content = f.read()
                st.session_state["sample_bytes"] = content
                st.session_state["sample_name"] = sample_choice
                st.rerun()
    st.stop()

# Support loading sample via session state
file_bytes = uploaded.read() if uploaded else st.session_state.get("sample_bytes", b"")
file_name = uploaded.name if uploaded else st.session_state.get("sample_name", "sample.csv")

# ──────────────────────────────────────────────
# Load data
# ──────────────────────────────────────────────
with tempfile.NamedTemporaryFile(
    delete=False, suffix=os.path.splitext(file_name)[1]
) as tmp:
    tmp.write(file_bytes)
    tmp_path = tmp.name

try:
    df = load_file(tmp_path)
except Exception as e:
    st.error(f"❌ Failed to load file: {e}")
    st.stop()

st.success(f"✅ Loaded **{file_name}** — {len(df):,} rows × {len(df.columns)} columns")

with st.expander("📋 Preview raw data (first 5 rows)"):
    st.dataframe(df.head(), use_container_width=True)

# ──────────────────────────────────────────────
# Scan
# ──────────────────────────────────────────────
if st.button("🔍 Scan for PII", type="primary", use_container_width=True):
    progress = st.progress(0, text="Step 1/4 – Running regex scanner…")

    # Step 1: Regex scan
    masked_df, findings_df = scan_dataframe(df)
    progress.progress(35, text="Step 2/4 – Running LLM column analysis…")

    # Step 2: LLM column scan (on first 5 rows)
    llm_col_findings: dict = {}
    if api_key:
        try:
            sample_rows = df.head(5).to_dict(orient="records")
            llm_col_findings = llm_scan_sample(sample_rows)
        except Exception as e:
            st.warning(f"⚠️ LLM column scan failed: {e}. Regex results only.")
    else:
        st.warning("⚠️ No API key – LLM scan skipped. Regex results only.")

    progress.progress(60, text="Step 3/4 – Building report…")

    # Step 3: Column risk summary
    col_summary = column_risk_summary(findings_df, df)

    # PII type counts
    pii_counts: dict = {}
    if not findings_df.empty:
        pii_counts = findings_df["pii_type"].value_counts().to_dict()

    # Step 4: LLM narrative report
    report_md = ""
    if api_key:
        try:
            report_md = llm_generate_report(
                filename=file_name,
                total_rows=len(df),
                column_summary=col_summary,
                pii_type_counts=pii_counts,
                sample_findings=findings_df.to_dict("records") if not findings_df.empty else [],
            )
        except Exception as e:
            st.warning(f"⚠️ LLM report generation failed: {e}")
            report_md = _build_fallback_report(file_name, len(df), col_summary, pii_counts)
    else:
        report_md = _build_fallback_report(file_name, len(df), col_summary, pii_counts)

    progress.progress(100, text="✅ Scan complete!")

    # ──────────────────────────────────────────────
    # Results
    # ──────────────────────────────────────────────
    st.markdown("---")

    # KPI cards
    total_pii = len(findings_df) if not findings_df.empty else 0
    affected_cols = findings_df["column"].nunique() if not findings_df.empty else 0
    affected_rows = findings_df["row"].nunique() if not findings_df.empty else 0

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Total PII Hits", total_pii)
    k2.metric("Affected Columns", affected_cols)
    k3.metric("Affected Rows", affected_rows)
    k4.metric("LLM Column Flags", len(llm_col_findings))

    tab1, tab2, tab3, tab4 = st.tabs(
        ["🔎 Findings", "🗂️ Masked Data", "📊 Risk Summary", "📄 Audit Report"]
    )

    with tab1:
        st.subheader("Detected PII Instances")
        if findings_df.empty:
            st.success("🎉 No PII detected by regex scan!")
        else:
            st.dataframe(findings_df, use_container_width=True)

        if llm_col_findings:
            st.subheader("🤖 LLM Column Analysis")
            for col, types in llm_col_findings.items():
                badges = " ".join(format_pii_badge(t) for t in types)
                st.markdown(f"**`{col}`** → {badges}")

    with tab2:
        st.subheader("Masked Dataset Preview")
        st.dataframe(masked_df.head(20), use_container_width=True)

        # Download masked CSV
        csv_buf = io.StringIO()
        masked_df.to_csv(csv_buf, index=False)
        st.download_button(
            "⬇️ Download Masked CSV",
            data=csv_buf.getvalue(),
            file_name=f"masked_{timestamp()}_{file_name.rsplit('.', 1)[0]}.csv",
            mime="text/csv",
        )

    with tab3:
        st.subheader("Column-Level Risk Summary")
        if col_summary:
            risk_df = pd.DataFrame(col_summary)
            st.dataframe(risk_df, use_container_width=True)

            # PII type distribution
            if pii_counts:
                st.subheader("PII Type Distribution")
                dist_df = pd.DataFrame(
                    list(pii_counts.items()), columns=["PII Type", "Count"]
                ).sort_values("Count", ascending=False)
                st.bar_chart(dist_df.set_index("PII Type"))
        else:
            st.info("No PII found – no risk summary to display.")

    with tab4:
        st.subheader("Audit Report")
        st.markdown(report_md)
        st.download_button(
            "⬇️ Download Audit Report (.md)",
            data=report_md,
            file_name=f"pii_audit_report_{timestamp()}.md",
            mime="text/markdown",
        )

    # Save outputs locally (for GitHub demo)
    os.makedirs("outputs", exist_ok=True)
    ts = timestamp()
    masked_df.to_csv(f"outputs/masked_{ts}.csv", index=False)
    if not findings_df.empty:
        findings_df.to_csv(f"outputs/findings_{ts}.csv", index=False)
    with open(f"outputs/audit_report_{ts}.md", "w") as f:
        f.write(report_md)

    st.caption(f"📁 Outputs also saved to `outputs/` folder (timestamp: {ts})")


def _build_fallback_report(
    filename: str, total_rows: int, col_summary: list, pii_counts: dict
) -> str:
    lines = [
        f"# PII Audit Report – {filename}",
        "",
        f"**Total rows scanned:** {total_rows}",
        "",
        "## PII Types Found",
    ]
    for k, v in pii_counts.items():
        lines.append(f"- {k}: {v} instances")
    lines += ["", "## Column Risk Summary"]
    for c in col_summary:
        lines.append(
            f"- **{c['column']}**: {c['pii_types_found']} | "
            f"Risk: {c['risk_level']} | Exposure: {c['exposure_pct']}%"
        )
    lines += [
        "",
        "## Recommendations",
        "- Mask or tokenize all PII columns before sharing data.",
        "- Apply role-based access controls to raw datasets.",
        "- Review free-text fields for embedded PII not caught by regex.",
        "- Ensure compliance with DPDP Act 2023 and GDPR.",
    ]
    return "\n".join(lines)
