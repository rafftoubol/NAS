package report

import (
	"attack-surface/src/scanner/codeScanner"
	"attack-surface/src/scanner/depScanner"
	"fmt"
	"github.com/johnfercher/maroto/pkg/color"
	"github.com/johnfercher/maroto/pkg/consts"
	"github.com/johnfercher/maroto/pkg/pdf"
	"github.com/johnfercher/maroto/pkg/props"
	"github.com/sirupsen/logrus"
	"strings"
)

type Report struct {
	CodeReport   *codeScanner.CodeScanReport
	DepReport    *depScanner.Response
	DepDevReport *depScanner.Response
}

func GeneratePDF(r *Report, outputPath string) error {
	logrus.Debug("Generating Report")

	m := pdf.NewMaroto(consts.Portrait, consts.A4)
	m.SetPageMargins(10, 10, 10)
	m.RegisterFooter(func() {
		m.Row(8, func() {
			m.Col(6, func() {
				currentPage := m.GetCurrentPage() + 1
				m.Text(fmt.Sprintf("Page %d", currentPage), props.Text{
					Style: consts.Italic,
					Size:  10,
					Align: consts.Right,
					Color: getDarkGrayColor(),
				})
			})
		})
	})

	// Add header with ASCII art and title
	addHeader(m)

	// Add executive summary
	addExecutiveSummary(m, r)

	// Check what content we have
	hasCodeContent := hasCodeScanContent(r.CodeReport)
	hasDepContent := hasDependencyContent(r.DepReport)
	hasDevDepContent := hasDependencyContent(r.DepDevReport)
	hasAnyContent := hasCodeContent || hasDepContent || hasDevDepContent

	if !hasAnyContent {
		addNoVulnerabilitiesMessage(m)
		return m.OutputFileAndClose(outputPath)
	}

	// Add detailed sections only if content exists
	if hasDepContent {
		addDependencySection(m, r.DepReport, "Dependencies")
	}

	if hasDevDepContent {
		addDependencySection(m, r.DepDevReport, "Dev Dependencies")
	}

	if hasCodeContent {
		addCodeVulnerabilitySection(m, r.CodeReport)
	}

	return m.OutputFileAndClose(outputPath)
}

// addHeader creates the ASCII art header and title
func addHeader(m pdf.Maroto) {
	asciiLines := []string{
		" ________   ________  ________      ",
		"|\\   ___  \\|\\   **  \\|\\   **__\\     ",
		"\\ \\  \\\\ \\  \\ \\  \\|\\  \\ \\  \\___|_    ",
		" \\ \\  \\\\ \\  \\ \\   **  \\ \\**___  \\   ",
		"  \\ \\  \\\\ \\  \\ \\  \\ \\  \\|____|\\  \\  ",
		"   \\ \\__\\\\ \\__\\ \\__\\ \\__\\____\\_\\  \\ ",
		"    \\|__| \\|__|\\|__|\\|__|\\_________\\",
		"                        \\|_________|",
	}

	for _, line := range asciiLines {
		m.Row(3, func() {
			m.Col(12, func() {
				m.Text(line, props.Text{
					Top:    0,
					Style:  consts.Bold,
					Size:   8,
					Color:  getDangerColor(),
					Align:  consts.Center,
					Family: consts.Courier,
				})
			})
		})
	}

	m.Row(4, func() {})

	m.Row(4, func() {
		m.Col(12, func() {
			m.Text("Security Report", props.Text{
				Top:    0,
				Style:  consts.Bold,
				Size:   24,
				Color:  getDangerColor(),
				Align:  consts.Center,
				Family: consts.Arial,
			})
		})
	})

	m.Row(12, func() {})
}

func addExecutiveSummary(m pdf.Maroto, report *Report) {
	m.Row(6, func() {
		m.Col(12, func() {
			m.Text("Executive Summary", props.Text{
				Style: consts.Bold,
				Size:  18,
				Color: getDangerColor(),
				Align: consts.Left,
			})
		})
	})
	m.Row(2, func() {})
	m.Row(2, func() {
		m.Col(12, func() {
			m.Line(1, props.Line{
				Color: getDangerColor(),
				Style: consts.Solid,
			})
		})
	})

	m.Row(4, func() {})

	// Count total vulnerabilities
	codeVulns, depVulns, devDepVulns := countVulnerabilities(report)
	totalVulns := codeVulns + depVulns + devDepVulns

	// Create summary text based on what was found
	var summaryText string
	if totalVulns == 0 {
		summaryText = "This security assessment found no vulnerabilities in the scanned Next.js application. The codebase appears to follow security best practices."
	} else {
		summaryText = fmt.Sprintf("This security assessment identified %d total vulnerabilities across the scanned Next.js application.", totalVulns)

		var details []string
		if codeVulns > 0 {
			details = append(details, fmt.Sprintf("code analysis found %d potential security issues", codeVulns))
		}
		if depVulns > 0 {
			details = append(details, fmt.Sprintf("dependency analysis identified %d vulnerabilities", depVulns))
		}
		if devDepVulns > 0 {
			details = append(details, fmt.Sprintf("dev dependency analysis identified %d vulnerabilities", devDepVulns))
		}

		if len(details) > 0 {
			summaryText += " Specifically, " + strings.Join(details, ", ") + "."
		}
	}

	addParagraphText(m, summaryText)

	m.Row(8, func() {})
}

// countVulnerabilities counts vulnerabilities across all scan types
func countVulnerabilities(report *Report) (int, int, int) {
	codeVulns := 0
	depVulns := 0
	devDepVulns := 0

	if report.CodeReport != nil {
		codeVulns = len(report.CodeReport.Methods) + len(report.CodeReport.CORS) +
			len(report.CodeReport.RCE) + len(report.CodeReport.ApiKey) +
			len(report.CodeReport.CoomentsSecrets)
	}

	if report.DepReport != nil {
		for _, result := range report.DepReport.Results {
			depVulns += len(result.Vulns)
		}
	}

	if report.DepDevReport != nil {
		for _, result := range report.DepDevReport.Results {
			devDepVulns += len(result.Vulns)
		}
	}

	return codeVulns, depVulns, devDepVulns
}

// addCodeVulnerabilitySection adds all code-related vulnerabilities in one section
func addCodeVulnerabilitySection(m pdf.Maroto, codeReport *codeScanner.CodeScanReport) {
	if codeReport == nil {
		return
	}

	codeVulns, _, _ := countVulnerabilities(&Report{CodeReport: codeReport})
	if codeVulns == 0 {
		return
	}

	addSectionTitle(m, fmt.Sprintf("Code Vulnerabilities (%d)", codeVulns))

	// Add each type of vulnerability with consistent formatting
	addCodeVulnerabilityType(m, "Unsafe Methods", codeReport.Methods)
	addCodeVulnerabilityType(m, "CORS Issues", codeReport.CORS)
	addCodeVulnerabilityType(m, "Remote Code Execution", codeReport.RCE)
	addCodeVulnerabilityType(m, "API Keys", codeReport.ApiKey)
	addCodeVulnerabilityType(m, "Commented Secrets", codeReport.CoomentsSecrets)

	m.Row(8, func() {})
}

func addCodeVulnerabilityType(m pdf.Maroto, vulnType string, vulnerabilities []codeScanner.Vulnerability) {
	if len(vulnerabilities) == 0 {
		return
	}

	addSectionTitle(m, fmt.Sprintf("%s (%d)", vulnType, len(vulnerabilities)))

	for i, vuln := range vulnerabilities {
		m.Row(5, func() {
			m.Col(8, func() {
				m.Text(fmt.Sprintf("%s #%d: %s", vulnType, i+1, vuln.Type), props.Text{
					Style: consts.Bold,
					Size:  14,
					Color: getDangerColor(),
					Align: consts.Left,
				})
			})
			m.Col(4, func() {
				m.Text(fmt.Sprintf("Line %d", vuln.Line), props.Text{
					Style: consts.Italic,
					Size:  10,
					Color: getDarkGrayColor(),
					Align: consts.Right,
				})
			})
		})

		// File path
		m.Row(3, func() {
			m.Col(12, func() {
				m.Text(fmt.Sprintf("File: %s", vuln.Path), props.Text{
					Style: consts.Italic,
					Size:  9,
					Color: getDarkGrayColor(),
					Align: consts.Left,
				})
			})
		})

		// Code block
		addCodeBlock(m, vuln.Content)

		m.Row(6, func() {})
	}
}

func addDependencySection(m pdf.Maroto, depReport *depScanner.Response, sectionTitle string) {
	if !hasDependencyContent(depReport) {
		return
	}

	totalVulns := 0
	for _, result := range depReport.Results {
		totalVulns += len(result.Vulns)
	}

	addSectionTitle(m, fmt.Sprintf("Dependencies (%d)", totalVulns))

	m.Row(4, func() {})

	for _, result := range depReport.Results {
		for _, vuln := range result.Vulns {
			addDependencyVulnerabilityBlock(m, vuln)
		}
	}

	m.Row(8, func() {})
}

func addDependencyVulnerabilityBlock(m pdf.Maroto, vuln depScanner.Vuln) {
	m.Row(5, func() {
		m.Col(8, func() {
			m.Text(fmt.Sprintf("Vulnerability: %s", vuln.ID), props.Text{
				Style: consts.Bold,
				Size:  12,
				Color: getBlackColor(),
				Align: consts.Left,
			})
		})
		m.Col(4, func() {
			if len(vuln.Aliases) > 0 {
				m.Text(fmt.Sprintf("Aliases: %s", strings.Join(vuln.Aliases, ", ")), props.Text{
					Style: consts.Italic,
					Size:  8,
					Color: getDarkGrayColor(),
					Align: consts.Right,
				})
			}
		})
	})

	// Summary
	if vuln.Summary != "" {
		m.Row(2, func() {})
		addParagraphText(m, vuln.Summary)
	}

	// Details if available
	if vuln.Details != "" {
		addCodeBlock(m, vuln.Details)
	}

	m.Row(15, func() {})
}

func addNoVulnerabilitiesMessage(m pdf.Maroto) {
	addSectionTitle(m, "Scan Results")

	m.Row(8, func() {
		m.Col(12, func() {
			m.Text("✓ No security vulnerabilities detected", props.Text{
				Style: consts.Bold,
				Size:  14,
				Color: getSuccessColor(),
				Align: consts.Center,
			})
		})
	})

	addParagraphText(m, "The security scan completed successfully with no vulnerabilities found in the codebase or dependencies. This indicates that the application follows security best practices.")

	m.Row(8, func() {})
}

func addSectionTitle(m pdf.Maroto, title string) {
	m.Row(6, func() {
		m.Col(12, func() {
			m.Text(title, props.Text{
				Style: consts.Bold,
				Size:  16,
				Color: getDangerColor(),
				Align: consts.Left,
			})
		})
	})

	m.Row(6, func() {})
}

func addParagraphText(m pdf.Maroto, text string) {
	m.Row(6, func() {
		m.Col(12, func() {
			m.Text(text, props.Text{
				Size:  11,
				Align: consts.Left,
				Color: getBlackColor(),
			})
		})
	})
}

func addCodeBlock(m pdf.Maroto, content string) {
	lines := strings.Split(content, "\n")
	rowHeight := float64(len(lines) + 2) // Adjust height for better spacing

	// Add top border
	m.Row(1, func() {
		m.Col(12, func() {
			m.Line(1, props.Line{
				Color: getDarkGrayColor(),
				Style: consts.Solid,
			})
		})
	})

	// Add code content with padding
	m.Row(rowHeight, func() {
		m.Col(12, func() {
			m.Text(fmt.Sprintf("  %s  ", strings.ReplaceAll(content, "\n", "\n  ")), props.Text{
				Top:    1,
				Size:   8,
				Color:  getBlackColor(),
				Align:  consts.Left,
				Family: consts.Courier,
			})
		})
	})

	m.Row(2, func() {})
}

func hasCodeScanContent(codeReport *codeScanner.CodeScanReport) bool {
	if codeReport == nil {
		return false
	}
	return len(codeReport.Methods) > 0 ||
		len(codeReport.CORS) > 0 ||
		len(codeReport.RCE) > 0 ||
		len(codeReport.ApiKey) > 0 ||
		len(codeReport.CoomentsSecrets) > 0
}

func hasDependencyContent(depReport *depScanner.Response) bool {
	if depReport == nil || len(depReport.Results) == 0 {
		return false
	}

	for _, result := range depReport.Results {
		if len(result.Vulns) > 0 {
			return true
		}
	}
	return false
}

// Color helper functions
func getDangerColor() color.Color {
	return color.Color{Red: 200, Green: 0, Blue: 0}
}

func getSuccessColor() color.Color {
	return color.Color{Red: 0, Green: 128, Blue: 0}
}

func getDarkGrayColor() color.Color {
	return color.Color{Red: 64, Green: 64, Blue: 64}
}

func getBlackColor() color.Color {
	return color.Color{Red: 0, Green: 0, Blue: 0}
}
