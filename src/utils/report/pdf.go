package report

import (
	"attack-surface/src/scanner/codeScanner"
	"attack-surface/src/scanner/depScanner"
	"fmt"
	"github.com/johnfercher/maroto/pkg/consts"
	"github.com/johnfercher/maroto/pkg/pdf"
	"github.com/johnfercher/maroto/pkg/props"
	"github.com/sirupsen/logrus"
)

type Report struct {
	CodeReport   *codeScanner.CodeScanReport
	DepReport    *depScanner.Response
	DepDevReport *depScanner.Response
}

// TODO: Expand with all data
// Just for the POC.
func GeneratePDF(r *Report, outputPath string) error {
	logrus.Debug("Generating Report")

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

	for i, result := range r.DepReport.Results {
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

	for i, result := range r.DepDevReport.Results {
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

		m.Row(10, func() {
			m.Col(12, func() {
				m.Text("Code Scan Results", props.Text{
					Style: consts.Bold,
					Size:  14,
				})
			})
		})

		printIfNotEmpty(m, "Methods", r.CodeReport.Methods)
		printIfNotEmpty(m, "CORS", r.CodeReport.CORS)
		printIfNotEmpty(m, "RCE", r.CodeReport.RCE)
		printIfNotEmpty(m, "API Keys", r.CodeReport.ApiKey)
		printIfNotEmpty(m, "Commented Secrets", r.CodeReport.CoomentsSecrets)

		if len(r.CodeReport.Methods) == 0 && len(r.CodeReport.CORS) == 0 && len(r.CodeReport.RCE) == 0 &&
			len(r.CodeReport.ApiKey) == 0 && len(r.CodeReport.CoomentsSecrets) == 0 {

			m.Row(6, func() {
				m.Col(12, func() {
					m.Text("No vulnerabilities found", props.Text{
						Style: consts.Italic,
					})
				})
			})
		}
	}

	return m.OutputFileAndClose(outputPath)
}

func printIfNotEmpty(m pdf.Maroto, title string, vulns []codeScanner.Vulnerability) {
	if len(vulns) == 0 {
		return
	}

	m.Row(6, func() {
		m.Col(12, func() {
			m.Text(title, props.Text{
				Style: consts.Bold,
			})
		})
	})

	for _, v := range vulns {
		m.Row(6, func() {
			m.Col(12, func() {
				m.Text(fmt.Sprintf("• %s:%d [%s] - %s", v.Path, v.Line, v.Type, v.Content), props.Text{
					Size: 9,
				})
			})
		})
	}
}
