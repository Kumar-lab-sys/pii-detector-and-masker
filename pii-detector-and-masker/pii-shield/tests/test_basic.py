"""
test_basic.py – Happy-path and edge-case tests for PII Shield.
Run: pytest tests/test_basic.py -v
"""

import sys
import os
import pandas as pd
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from processor import detect_regex, mask_text, scan_dataframe, load_file, column_risk_summary


# ──────────────────────────────────────────────
# detect_regex tests
# ──────────────────────────────────────────────

class TestDetectRegex:
    def test_detects_email(self):
        hits = detect_regex("Contact me at john.doe@example.com")
        assert any(h["pii_type"] == "EMAIL" for h in hits)

    def test_detects_indian_phone_10digit(self):
        hits = detect_regex("Call 9876543210 now")
        assert any(h["pii_type"] == "PHONE_IN" for h in hits)

    def test_detects_phone_with_country_code(self):
        hits = detect_regex("My number is +91-9123456789")
        assert any(h["pii_type"] == "PHONE_IN" for h in hits)

    def test_detects_pan(self):
        hits = detect_regex("PAN number: ABCDE1234F")
        assert any(h["pii_type"] == "PAN" for h in hits)

    def test_detects_aadhaar_spaced(self):
        hits = detect_regex("Aadhaar: 1234 5678 9012")
        assert any(h["pii_type"] == "AADHAAR" for h in hits)

    def test_detects_aadhaar_no_spaces(self):
        hits = detect_regex("UID: 123456789012")
        assert any(h["pii_type"] == "AADHAAR" for h in hits)

    def test_no_pii_clean_text(self):
        hits = detect_regex("This is a clean sentence with no personal data.")
        assert hits == []

    def test_multiple_pii_in_one_cell(self):
        text = "Email: foo@bar.com, Phone: 9988776655, PAN: XYZAB1234C"
        hits = detect_regex(text)
        types = {h["pii_type"] for h in hits}
        assert "EMAIL" in types
        assert "PHONE_IN" in types
        assert "PAN" in types


# ──────────────────────────────────────────────
# mask_text tests
# ──────────────────────────────────────────────

class TestMaskText:
    def test_email_is_masked(self):
        hits = detect_regex("test@example.com")
        result = mask_text("test@example.com", hits)
        assert "@" in result  # structure preserved
        assert "test@example.com" not in result  # original gone

    def test_pan_is_masked(self):
        hits = detect_regex("ABCDE1234F")
        result = mask_text("ABCDE1234F", hits)
        assert "ABCDE1234F" not in result
        assert "*" in result

    def test_aadhaar_masked_shows_last_4(self):
        hits = detect_regex("1234 5678 9012")
        result = mask_text("1234 5678 9012", hits)
        assert "9012" in result  # last 4 digits preserved
        assert "1234" not in result  # first group hidden

    def test_clean_text_unchanged(self):
        text = "No PII here."
        hits = detect_regex(text)
        assert mask_text(text, hits) == text


# ──────────────────────────────────────────────
# scan_dataframe tests
# ──────────────────────────────────────────────

class TestScanDataframe:
    def _sample_df(self):
        return pd.DataFrame(
            {
                "id": [1, 2, 3],
                "email": ["alice@example.com", "bob@test.org", "clean"],
                "phone": ["9876543210", "no phone", "+91-8123456789"],
                "notes": ["PAN: ABCDE1234F", "normal note", "Aadhaar 1234 5678 9012"],
            }
        )

    def test_returns_masked_df_and_findings(self):
        df = self._sample_df()
        masked, findings = scan_dataframe(df)
        assert isinstance(masked, pd.DataFrame)
        assert isinstance(findings, pd.DataFrame)

    def test_masked_df_same_shape(self):
        df = self._sample_df()
        masked, _ = scan_dataframe(df)
        assert masked.shape == df.shape

    def test_findings_not_empty_when_pii_present(self):
        df = self._sample_df()
        _, findings = scan_dataframe(df)
        assert not findings.empty

    def test_findings_has_correct_columns(self):
        df = self._sample_df()
        _, findings = scan_dataframe(df)
        assert set(["row", "column", "pii_type", "original_value"]).issubset(findings.columns)

    def test_email_column_flagged(self):
        df = self._sample_df()
        _, findings = scan_dataframe(df)
        assert "email" in findings["column"].values

    def test_original_values_not_in_masked(self):
        df = self._sample_df()
        masked, _ = scan_dataframe(df)
        assert "alice@example.com" not in masked.to_csv()
        assert "ABCDE1234F" not in masked.to_csv()

    def test_clean_df_returns_empty_findings(self):
        clean_df = pd.DataFrame({"name": ["Alice", "Bob"], "city": ["Delhi", "Mumbai"]})
        _, findings = scan_dataframe(clean_df)
        assert findings.empty


# ──────────────────────────────────────────────
# load_file tests
# ──────────────────────────────────────────────

class TestLoadFile:
    def test_load_csv(self, tmp_path):
        p = tmp_path / "test.csv"
        p.write_text("a,b\n1,2\n3,4\n")
        df = load_file(str(p))
        assert len(df) == 2
        assert list(df.columns) == ["a", "b"]

    def test_load_json(self, tmp_path):
        import json
        p = tmp_path / "test.json"
        p.write_text(json.dumps([{"x": 1}, {"x": 2}]))
        df = load_file(str(p))
        assert len(df) == 2

    def test_unsupported_format_raises(self, tmp_path):
        p = tmp_path / "test.xlsx"
        p.write_text("data")
        with pytest.raises(ValueError, match="Unsupported"):
            load_file(str(p))


# ──────────────────────────────────────────────
# column_risk_summary tests
# ──────────────────────────────────────────────

class TestColumnRiskSummary:
    def test_returns_list(self):
        df = pd.DataFrame({"email": ["a@b.com", "c@d.com"]})
        _, findings = scan_dataframe(df)
        result = column_risk_summary(findings, df)
        assert isinstance(result, list)

    def test_empty_findings_returns_empty(self):
        df = pd.DataFrame({"name": ["Alice"]})
        findings = pd.DataFrame(columns=["row", "column", "pii_type", "original_value"])
        result = column_risk_summary(findings, df)
        assert result == []

    def test_high_risk_when_majority_affected(self):
        emails = [f"user{i}@example.com" for i in range(20)]
        df = pd.DataFrame({"email": emails})
        _, findings = scan_dataframe(df)
        summary = column_risk_summary(findings, df)
        assert summary[0]["risk_level"] == "HIGH"
