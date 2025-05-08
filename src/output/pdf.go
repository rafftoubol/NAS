package output

import (
	"attack-surface/src/api"
	"fmt"
	"github.com/johnfercher/maroto/pkg/color"
	"github.com/johnfercher/maroto/pkg/consts"
	"github.com/johnfercher/maroto/pkg/pdf"
	"github.com/johnfercher/maroto/pkg/props"
	"time"
)

var (
	// VU Colors
	vuRed     = color.Color{190, 0, 0}     // Primary VU red
	vuGray    = color.Color{128, 130, 133} // Secondary gray
	lightGray = color.Color{242, 242, 242} // Background color
)

type PDFExporter struct {
	results *CombinedResults
}

func NewPDFExporter(results *CombinedResults) *PDFExporter {
	return &PDFExporter{results: results}
}

func (e *PDFExporter) Export(filename string) error {
	m := pdf.NewMaroto(consts.Portrait, consts.A4)
	m.SetPageMargins(20, 10, 20)

	// Add header with VU branding
	e.addHeader(m)

	// Add executive summary
	e.addExecutiveSummary(m)

	// Add statistics section
	e.addStatistics(m)

	// Add main content
	e.addVulnerabilityDetails(m)

	// Add recommendations
	e.addRecommendations(m)

	// Add footer
	e.addFooter(m)

	return m.OutputFileAndClose(filename)
}

func (e *PDFExporter) addHeader(m pdf.Maroto) {
	m.RegisterHeader(func() {
		m.Row(20, func() {
			m.Col(12, func() {
				m.Text("Security Analysis Report", props.Text{
					Size:  16,
					Style: consts.Bold,
					Color: vuRed,
				})
			})
		})
		m.Row(10, func() {
			m.Col(12, func() {
				m.Text("Vilnius University", props.Text{
					Size:  12,
					Color: vuGray,
				})
			})
		})
	})
}

func (e *PDFExporter) addExecutiveSummary(m pdf.Maroto) {
	m.Row(15, func() {
		m.Col(12, func() {
			m.Text("Executive Summary", props.Text{
				Size:  14,
				Style: consts.Bold,
				Color: vuRed,
			})
		})
	})

	// Calculate API vulnerabilities
	apiVulnerabilities := len(e.results.APIs.Methods) + len(e.results.APIs.CORS) +
		len(e.results.APIs.RCE) + len(e.results.APIs.ApiKey) + len(e.results.APIs.CoomentsSecrets)

	// Calculate dependency vulnerabilities
	depVulnerabilities := 0
	if e.results.Dependencies != nil {
		depVulnerabilities = len(e.results.Dependencies.Vulnerabilities)
	}

	totalVulnerabilities := apiVulnerabilities + depVulnerabilities

	// Add summary text
	m.Row(10, func() {
		m.Col(12, func() {
			m.Text(fmt.Sprintf(
				"This security analysis identified %d total potential security issues across multiple categories:",
				totalVulnerabilities,
			), props.Text{Size: 10})
		})
	})

	// Add breakdown of vulnerabilities
	m.Row(8, func() {
		m.Col(12, func() {
			m.Text(fmt.Sprintf(
				"• %d API-related security issues\n• %d dependency-related vulnerabilities",
				apiVulnerabilities,
				depVulnerabilities,
			), props.Text{
				Size:  10,
				Style: consts.Normal,
			})
		})
	})

	// Add severity breakdown for dependencies if available
	if e.results.Dependencies != nil && len(e.results.Dependencies.Vulnerabilities) > 0 {
		// Count vulnerabilities by severity
		severityCount := make(map[string]int)
		for _, v := range e.results.Dependencies.Vulnerabilities {
			severityCount[v.Severity]++
		}

		m.Row(10, func() {
			m.Col(12, func() {
				severityText := "\nDependency vulnerability breakdown by severity:"
				for severity, count := range severityCount {
					severityText += fmt.Sprintf("\n• %s: %d", severity, count)
				}
				m.Text(severityText, props.Text{Size: 10})
			})
		})
	}

	// Add recommendation summary
	m.Row(12, func() {
		m.Col(12, func() {
			m.Text("Immediate attention is recommended for critical vulnerabilities and exposed secrets. "+
				"A detailed breakdown of all findings and specific recommendations can be found in the following sections.",
				props.Text{
					Size:  10,
					Style: consts.Italic,
				})
		})
	})
}

func (e *PDFExporter) addStatistics(m pdf.Maroto) {
	m.Row(15, func() {
		m.Col(12, func() {
			m.Text("Analysis Statistics", props.Text{
				Size:  14,
				Style: consts.Bold,
				Color: vuRed,
			})
		})
	})

	// Create statistics table
	headers := []string{"Vulnerability Type", "Count", "Risk Level"}
	contents := [][]string{
		{"HTTP Methods", fmt.Sprintf("%d", len(e.results.APIs.Methods)), "Low-Medium"},
		{"CORS Misconfigurations", fmt.Sprintf("%d", len(e.results.APIs.CORS)), "Medium-High"},
		{"Remote Code Execution", fmt.Sprintf("%d", len(e.results.APIs.RCE)), "Critical"},
		{"API Key Exposure", fmt.Sprintf("%d", len(e.results.APIs.ApiKey)), "High"},
		{"Secrets in Comments", fmt.Sprintf("%d", len(e.results.APIs.CoomentsSecrets)), "High"},
	}

	m.TableList(headers, contents, props.TableList{
		HeaderProp: props.TableListContent{
			Size:      11,
			Style:     consts.Bold,
			GridSizes: []uint{5, 2, 5},
		},
		ContentProp: props.TableListContent{
			Size:      10,
			GridSizes: []uint{5, 2, 5},
		},
		Align:                consts.Left,
		AlternatedBackground: &lightGray,
		HeaderContentSpace:   2,
		Line:                 false,
	})

	// Add total vulnerabilities
	totalVulns := len(e.results.APIs.Methods) + len(e.results.APIs.CORS) + len(e.results.APIs.RCE) +
		len(e.results.APIs.ApiKey) + len(e.results.APIs.CoomentsSecrets)

	m.Row(10, func() {
		m.Col(12, func() {
			m.Text(fmt.Sprintf("Total Vulnerabilities Found: %d", totalVulns),
				props.Text{
					Size:  11,
					Style: consts.Bold,
				})
		})
	})
}

// dependency vulnerabilities
func (e *PDFExporter) addDependencySection(m pdf.Maroto) {
	if e.results.Dependencies == nil || len(e.results.Dependencies.Vulnerabilities) == 0 {
		return
	}

	m.Row(15, func() {
		m.Col(12, func() {
			m.Text("Dependency Vulnerabilities", props.Text{
				Size:  14,
				Style: consts.Bold,
				Color: vuRed,
			})
		})
	})

	headers := []string{"Package", "Version", "Severity", "Details"}
	var contents [][]string
	for _, v := range e.results.Dependencies.Vulnerabilities {
		contents = append(contents, []string{
			v.PackageName,
			v.Version,
			v.Severity,
			v.Details,
		})
	}

	m.TableList(headers, contents, props.TableList{
		HeaderProp: props.TableListContent{
			Size:      10,
			Style:     consts.Bold,
			GridSizes: []uint{3, 2, 2, 5},
		},
		ContentProp: props.TableListContent{
			Size:      9,
			GridSizes: []uint{3, 2, 2, 5},
		},
		Align:                consts.Left,
		AlternatedBackground: &lightGray,
		HeaderContentSpace:   1,
		Line:                 false,
	})
}

func (e *PDFExporter) addVulnerabilityDetails(m pdf.Maroto) {
	m.Row(15, func() {
		m.Col(12, func() {
			m.Text("Detailed Findings", props.Text{
				Size:  14,
				Style: consts.Bold,
				Color: vuRed,
			})
		})
	})

	// Add each vulnerability category
	if len(e.results.APIs.RCE) > 0 {
		e.addVulnerabilitySection(m, "Remote Code Execution (Critical)", e.results.APIs.RCE,
			"RCE vulnerabilities allow attackers to execute arbitrary code on the server. These issues require immediate attention.")
	}

	if len(e.results.APIs.ApiKey) > 0 {
		e.addVulnerabilitySection(m, "API Key Exposure (High)", e.results.APIs.ApiKey,
			"Exposed API keys can lead to unauthorized access and potential service abuse. All exposed keys should be rotated immediately.")
	}

	if len(e.results.APIs.CoomentsSecrets) > 0 {
		e.addVulnerabilitySection(m, "Secrets in Comments (High)", e.results.APIs.CoomentsSecrets,
			"Sensitive information found in code comments poses a security risk and should be removed.")
	}

	if len(e.results.APIs.CORS) > 0 {
		e.addVulnerabilitySection(m, "CORS Misconfigurations (Medium-High)", e.results.APIs.CORS,
			"CORS misconfigurations can lead to unauthorized access to sensitive data from malicious domains.")
	}

	if len(e.results.APIs.Methods) > 0 {
		e.addVulnerabilitySection(m, "HTTP Methods (Low-Medium)", e.results.APIs.Methods,
			"Certain HTTP methods might expose unnecessary functionality or lead to security issues if not properly restricted.")
	}
}

func (e *PDFExporter) addVulnerabilitySection(m pdf.Maroto, title string, vulns []api.Vulnerability, description string) {
	m.Row(10, func() {
		m.Col(12, func() {
			m.Text(title, props.Text{
				Size:  12,
				Style: consts.Bold,
			})
		})
	})

	m.Row(8, func() {
		m.Col(12, func() {
			m.Text(description, props.Text{
				Size: 10,
			})
		})
	})

	headers := []string{"File", "Line", "Finding"}
	var contents [][]string
	for _, v := range vulns {
		contents = append(contents, []string{
			v.Path,
			fmt.Sprintf("%d", v.Line),
			v.Content,
		})
	}

	m.TableList(headers, contents, props.TableList{
		HeaderProp: props.TableListContent{
			Size:      10,
			Style:     consts.Bold,
			GridSizes: []uint{4, 1, 7},
		},
		ContentProp: props.TableListContent{
			Size:      9,
			GridSizes: []uint{4, 1, 7},
		},
		Align:                consts.Left,
		AlternatedBackground: &lightGray,
		HeaderContentSpace:   1,
		Line:                 false,
	})

	// Add spacing after section
	m.Row(5, func() {})
}

func (e *PDFExporter) addRecommendations(m pdf.Maroto) {
	m.Row(15, func() {
		m.Col(12, func() {
			m.Text("Recommendations", props.Text{
				Size:  14,
				Style: consts.Bold,
				Color: vuRed,
			})
		})
	})

	recommendations := []struct {
		title string
		desc  string
	}{
		{
			"1. Address Critical Vulnerabilities",
			"Immediately fix any RCE vulnerabilities and rotate exposed API keys. Remove all hardcoded secrets from the codebase.",
		},
		{
			"2. Implement Secure CORS Policies",
			"Review and restrict CORS policies to only allow necessary origins. Avoid using wildcards (*) in production.",
		},
		{
			"3. Review HTTP Method Security",
			"Ensure HTTP methods are properly restricted and authenticated. Remove any unnecessary method handlers.",
		},
		{
			"4. Implement Security Headers",
			"Add appropriate security headers including Content-Security-Policy, X-Frame-Options, and X-Content-Type-Options.",
		},
		{
			"5. Regular Security Audits",
			"Establish a routine security audit process to catch potential vulnerabilities early in development.",
		},
	}

	for _, rec := range recommendations {
		m.Row(8, func() {
			m.Col(12, func() {
				m.Text(rec.title, props.Text{
					Size:  11,
					Style: consts.Bold,
				})
			})
		})
		m.Row(8, func() {
			m.Col(12, func() {
				m.Text(rec.desc, props.Text{
					Size: 10,
				})
			})
		})
	}
}

func (e *PDFExporter) addFooter(m pdf.Maroto) {
	m.RegisterFooter(func() {
		m.Row(10, func() {
			m.Col(12, func() {
				m.Text(fmt.Sprintf("Report generated on %s",
					time.Now().Format("January 2, 2006 15:04:05")),
					props.Text{
						Size:  8,
						Style: consts.Italic,
						Color: vuGray,
						Align: consts.Center,
					})
			})
		})
	})
}
