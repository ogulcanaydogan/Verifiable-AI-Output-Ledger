package verifier

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNewReportSetsFields(t *testing.T) {
	bundle := BundleResult{TotalRecords: 5, ValidRecords: 5}
	before := time.Now().UTC()
	report := NewReport("Test Audit", bundle)
	after := time.Now().UTC()

	if report.Title != "Test Audit" {
		t.Errorf("Title = %q, want 'Test Audit'", report.Title)
	}
	if report.Bundle.TotalRecords != 5 {
		t.Errorf("TotalRecords = %d, want 5", report.Bundle.TotalRecords)
	}
	if report.Generated.Before(before.Add(-time.Second)) || report.Generated.After(after.Add(time.Second)) {
		t.Errorf("Generated %v not within expected range", report.Generated)
	}
}

func TestReportToJSONValid(t *testing.T) {
	bundle := BundleResult{TotalRecords: 3, ValidRecords: 3, Summary: "VERIFICATION PASSED"}
	report := NewReport("JSON Test", bundle)

	data, err := report.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON error: %v", err)
	}

	// Round-trip: unmarshal back
	var parsed Report
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if parsed.Title != "JSON Test" {
		t.Errorf("Title after round-trip = %q, want 'JSON Test'", parsed.Title)
	}
	if parsed.Bundle.TotalRecords != 3 {
		t.Errorf("TotalRecords after round-trip = %d, want 3", parsed.Bundle.TotalRecords)
	}
}

func TestReportToMarkdownIncludesTitle(t *testing.T) {
	report := NewReport("Audit Report 2026", BundleResult{})
	md := report.ToMarkdown()

	if !strings.Contains(md, "# Audit Report 2026") {
		t.Error("markdown should contain '# Audit Report 2026'")
	}
}

func TestReportToMarkdownSummaryTable(t *testing.T) {
	bundle := BundleResult{
		TotalRecords:    10,
		ValidRecords:    8,
		InvalidRecords:  2,
		ChainIntact:     true,
		MerkleValid:     true,
		SignaturesValid: false,
		SchemaValid:     true,
	}
	report := NewReport("Summary Test", bundle)
	md := report.ToMarkdown()

	if !strings.Contains(md, "Total records") {
		t.Error("markdown should contain 'Total records'")
	}
	if !strings.Contains(md, "10") {
		t.Error("markdown should contain total record count '10'")
	}
	if !strings.Contains(md, "PASS") {
		t.Error("markdown should contain 'PASS' for passing checks")
	}
	if !strings.Contains(md, "FAIL") {
		t.Error("markdown should contain 'FAIL' for failing checks")
	}
}

func TestReportToMarkdownWithFailures(t *testing.T) {
	bundle := BundleResult{
		TotalRecords:   1,
		ValidRecords:   0,
		InvalidRecords: 1,
		Results: []Result{
			{
				RequestID: "req-123-abc",
				Valid:     false,
				Checks: []CheckResult{
					{Name: "signature", Passed: false, Error: "no valid signatures found"},
				},
			},
		},
	}
	report := NewReport("Failure Test", bundle)
	md := report.ToMarkdown()

	if !strings.Contains(md, "## Failures") {
		t.Error("markdown should contain '## Failures' section")
	}
	if !strings.Contains(md, "req-123-abc") {
		t.Error("markdown should contain the failing record's request ID")
	}
	if !strings.Contains(md, "signature") {
		t.Error("markdown should contain the failing check name")
	}
	if !strings.Contains(md, "no valid signatures found") {
		t.Error("markdown should contain the error message")
	}
}

func TestReportToMarkdownConclusion(t *testing.T) {
	bundle := BundleResult{Summary: "VERIFICATION PASSED"}
	report := NewReport("Conclusion Test", bundle)
	md := report.ToMarkdown()

	if !strings.Contains(md, "## Conclusion") {
		t.Error("markdown should contain '## Conclusion'")
	}
	if !strings.Contains(md, "VERIFICATION PASSED") {
		t.Error("markdown should contain 'VERIFICATION PASSED'")
	}
}

func TestPassFailIcon(t *testing.T) {
	if passFailIcon(true) != "PASS" {
		t.Errorf("passFailIcon(true) = %q, want PASS", passFailIcon(true))
	}
	if passFailIcon(false) != "FAIL" {
		t.Errorf("passFailIcon(false) = %q, want FAIL", passFailIcon(false))
	}
}
