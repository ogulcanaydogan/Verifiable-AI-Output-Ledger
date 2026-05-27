package verifier

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Report generates a human-readable verification report.
type Report struct {
	Title     string       `json:"title"`
	Generated time.Time    `json:"generated"`
	Bundle    BundleResult `json:"bundle"`
}

// NewReport creates a verification report from a bundle result.
func NewReport(title string, bundle BundleResult) *Report {
	return &Report{
		Title:     title,
		Generated: time.Now().UTC(),
		Bundle:    bundle,
	}
}

// ToJSON serializes the report as indented JSON.
func (r *Report) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ToMarkdown generates a Markdown-formatted verification report.
func (r *Report) ToMarkdown() string {
	var b strings.Builder

	fmt.Fprintf(&b, "# %s\n\n", r.Title)
	fmt.Fprintf(&b, "**Generated:** %s\n\n", r.Generated.Format(time.RFC3339))

	b.WriteString("## Summary\n\n")
	b.WriteString("| Metric | Value |\n")
	b.WriteString("|--------|-------|\n")
	fmt.Fprintf(&b, "| Total records | %d |\n", r.Bundle.TotalRecords)
	fmt.Fprintf(&b, "| Valid records | %d |\n", r.Bundle.ValidRecords)
	fmt.Fprintf(&b, "| Invalid records | %d |\n", r.Bundle.InvalidRecords)
	fmt.Fprintf(&b, "| Hash chain | %s |\n", passFailIcon(r.Bundle.ChainIntact))
	fmt.Fprintf(&b, "| Merkle proofs | %s |\n", passFailIcon(r.Bundle.MerkleValid))
	fmt.Fprintf(&b, "| Signatures | %s |\n", passFailIcon(r.Bundle.SignaturesValid))
	fmt.Fprintf(&b, "| Schema | %s |\n", passFailIcon(r.Bundle.SchemaValid))
	fmt.Fprintf(&b, "| Manifest | %s |\n", passFailIcon(r.Bundle.ManifestValid))
	b.WriteString("\n")

	if r.Bundle.InvalidRecords > 0 {
		b.WriteString("## Failures\n\n")
		for _, res := range r.Bundle.Results {
			if !res.Valid {
				fmt.Fprintf(&b, "### Record %s\n\n", res.RequestID)
				for _, check := range res.Checks {
					if !check.Passed {
						fmt.Fprintf(&b, "- **%s**: %s\n", check.Name, check.Error)
					}
				}
				b.WriteString("\n")
			}
		}
	}

	fmt.Fprintf(&b, "## Conclusion\n\n%s\n", r.Bundle.Summary)

	return b.String()
}

func passFailIcon(passed bool) string {
	if passed {
		return "PASS"
	}
	return "FAIL"
}
