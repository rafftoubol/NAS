package report

import (
	"attack-surface/src/scanner/depScanner"
	"fmt"
	"github.com/johnfercher/maroto/pkg/consts"
	"github.com/johnfercher/maroto/pkg/pdf"
	"github.com/johnfercher/maroto/pkg/props"
)

// TODO: Expand with all data
// Just for the POC.
func GeneratePDF(r *depScanner.Response, outputPath string) error {
	// Avoid passing the scanner.Report because it will cause a cyclic include.
	m := pdf.NewMaroto(consts.Portrait, consts.A4)
	m.SetPageMargins(10, 10, 10)

	m.Row(10, func() {
		m.Col(12, func() {
			m.Text("Scanner Report", props.Text{
				Top:   1,
				Style: consts.Bold,
				Size:  16,
			})
		})
	})
	m.Row(8, func() {
		m.Col(12, func() {
			m.Text("Report", props.Text{
				Style: consts.Bold,
				Size:  14,
			})
		})
	})

	for i, result := range r.Results {
		if len(result.Vulns) == 0 {
			continue
		}

		m.Row(6, func() {
			m.Col(12, func() {
				m.Text(fmt.Sprintf("Package #%d: %d vulnerabilities", i, len(result.Vulns)), props.Text{
					Style: consts.Bold,
				})
			})
		})

		for _, vuln := range result.Vulns {
			m.Row(6, func() {
				m.Col(12, func() {
					m.Text(fmt.Sprintf("- ID: %s, Modified: %s", vuln.ID, vuln.Modified), props.Text{})
				})
			})
		}
	}

	return m.OutputFileAndClose(outputPath)
}
