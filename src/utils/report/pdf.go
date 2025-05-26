package report

import (
	"attack-surface/src/scanner/codeScanner"
	"attack-surface/src/scanner/depScanner"
	"attack-surface/src/utils"
	"attack-surface/src/utils/config"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/phpdave11/gofpdf"
	"github.com/sirupsen/logrus"
)

type Report struct {
	CodeReport   *codeScanner.CodeScanReport
	DepReport    *depScanner.Response
	DepDevReport *depScanner.Response
}

type vulnTypeConfig struct {
	name       string
	vulns      []codeScanner.Vulnerability
	isCritical bool
}

var (
	bgLine = 12.0
	line   = 9.0
	smLine = 6.0
)

func GeneratePDF(r *Report, n *utils.Next, c *config.Config) error {
	logrus.Debug("Generating Report")

	linkMap := make(map[string]int)
	logo := `
 ________   ________  ________      
|\   ___  \|\   __  \|\   ____\     
\ \  \\ \  \ \  \|\  \ \  \___|_    
 \ \  \\ \  \ \   __  \ \_____  \   
  \ \  \\ \  \ \  \ \  \|____|\  \  
   \ \__\\ \__\ \__\ \__\____\_\  \ 
    \|__| \|__|\|__|\|__|\_________\
                        \|_________|`

	depCount := 0
	for range n.Dependencies {
		depCount++
	}
	devDepCount := 0
	for range n.DevDependencies {
		devDepCount++
	}

	// Settings Template
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AliasNbPages("")
	pdf.AddUTF8Font("BubisNeue", "", "font/BebasNeue-Regular.ttf")
	pdf.AddUTF8Font("Roboto", "", "font/Roboto-Regular.ttf")
	pdf.AddUTF8Font("Roboto", "I", "font/Roboto-Italic.ttf")
	pdf.SetMargins(10, 10, 10)
	pageWidth, pageHeight := pdf.GetPageSize()

	pdf.SetHeaderFuncMode(func() {
		pdf.SetY(10)
		pdf.SetFont("Courier", "B", 3)
		lines := strings.Split(strings.Trim(logo, "\n "), "\n")
		lineHeight := 0.9
		for _, line := range lines {
			strWidth := pdf.GetStringWidth(line)
			pdf.SetTextColor(120, 0, 63)
			pdf.SetX((pageWidth - strWidth) / 2)
			pdf.CellFormat(0, lineHeight, line, "", 1, "R", false, 0, "")
		}
		pdf.SetDrawColor(139, 74, 105)
		pdf.SetLineWidth(0.4)
		pdf.Line(10, 20, pageWidth-10, 20)
		pdf.Ln(15)
	}, false)

	pdf.SetFooterFunc(func() {

		pdf.SetDrawColor(139, 74, 105)
		pdf.SetLineWidth(0.4)
		pdf.Line(10, pageHeight-15, pageWidth-10, pageHeight-15)

		pdf.SetY(pageHeight - 15)
		pdf.SetFont("Roboto", "I", 10)
		pdf.CellFormat(0, 10, time.Now().Format("02/01/2006 15:04"), "", 0, "L", false, 0, "")
		pageInfo := fmt.Sprintf("Page %d of {nb}", pdf.PageNo())
		pdf.CellFormat(0, 10, pageInfo, "", 0, "R", false, 0, "")
	})

	// First Page
	pdf.AddPage()
	heading1("Next.js Project Summary", pdf)
	pdf.SetY(pdf.GetY() + line)

	nextTable := [][]string{
		{"Project title", n.Name},
		{"Version", n.Version},
		{"Description", n.Description},
		{"Author", n.Author},
		{"License", n.License},
		{"Keywords", strings.Join(n.Keyword, ", ")},
		{"Packages (Dependencies)", strconv.Itoa(depCount)},
		{"Packages (DevDependencies)", strconv.Itoa(devDepCount)},
	}

	tableH(pdf, nextTable)
	pdf.SetY(pdf.GetY() + line)
	heading3("Scanner Settings", pdf)
	pdf.SetY(pdf.GetY() + smLine)
	scannerSettings := [][]string{
		{"Project Path", "Output Path", "Code Scanner", "Dependencies Scanner"},
		{c.ProjectPath, c.OutputPath, strconv.FormatBool(c.CodeScan), strconv.FormatBool(c.DependenciesScan)},
	}
	tableV(pdf, scannerSettings)

	// Second Page
	pdf.AddPage()
	heading1("Scan Result", pdf)
	pdf.SetY(pdf.GetY() + bgLine)

	// Dep Scan Part
	heading2("Dependencies Scan", pdf)
	pdf.SetY(pdf.GetY() + line)
	if c.DependenciesScan {
		depScanResult(depCount+devDepCount, r, linkMap, pdf)
	} else {
		pdf.SetFont("Roboto", "", 10)
		pdf.CellFormat(0, 0, "Dependencies Scan is Skipped (Disabled).", "", 1, "L", false, 0, "")
	}
	pdf.SetY(pdf.GetY() + bgLine)

	// Code Scan Part
	pdf.SetY(pdf.GetY() + line)
	if c.CodeScan {
		codeScanResult(r, linkMap, pdf)
	} else {
		pdf.SetFont("Roboto", "", 10)
		pdf.CellFormat(0, 0, "Code Scan is Skipped (Disabled).", "", 1, "L", false, 0, "")
	}

	if c.DependenciesScan || c.CodeScan {
		// Third Page for vulnerability details
		if c.DependenciesScan {
			pdf.AddPage()
			pdf.SetFont("BubisNeue", "", 36)
			pdf.CellFormat(0, pageHeight/2+18, "Vulnerabilities Details", "", 1, "C", false, 0, "")
			vulnScanDetails(linkMap, r, pdf)
		}

		if c.CodeScan && r.CodeReport != nil && countCodeVulnerabilities(r.CodeReport) > 0 {
			pdf.AddPage()
			codeVulnScanDetails(linkMap, r, pdf)
		}
	}

	// Generation
	if err := pdf.OutputFileAndClose("generated.pdf"); err != nil {
		return err
	}

	input := []string{"src/utils/report/cover.pdf", "generated.pdf"}
	if err := api.MergeCreateFile(input, "report.pdf", false, nil); err != nil {
		return err
	}
	if err := os.Remove("generated.pdf"); err != nil {
		return err
	}
	return nil
}

func heading1(title string, pdf *gofpdf.Fpdf) {
	pdf.SetFont("BubisNeue", "", 32)
	pdf.CellFormat(0, 0, title, "", 1, "L", true, 0, "")
}

func heading2(title string, pdf *gofpdf.Fpdf) {
	pdf.SetFont("BubisNeue", "", 22)

	pdf.CellFormat(0, 0, title, "", 1, "L", true, 0, "")
}
func heading3(title string, pdf *gofpdf.Fpdf) {
	pdf.SetFont("BubisNeue", "", 18)
	pdf.CellFormat(0, 0, title, "", 1, "L", true, 0, "")
}

func tableH(pdf *gofpdf.Fpdf, rows [][]string) {
	pageWidth, _ := pdf.GetPageSize()
	marginLeft, _, marginRight, _ := pdf.GetMargins()
	usableWidth := pageWidth - marginLeft - marginRight

	col1Width := usableWidth * 0.3
	col2Width := usableWidth * 0.7
	lineHeight := 6.0

	for _, row := range rows {
		pdf.SetFont("Roboto", "", 10)
		lines := pdf.SplitText(row[1], col2Width)
		height := float64(len(lines)) * lineHeight

		y := pdf.GetY()
		x := pdf.GetX()

		pdf.SetFont("BubisNeue", "", 13)
		pdf.SetFillColor(200, 137, 154)
		pdf.Rect(x, y, col1Width, height, "F")
		pdf.MultiCell(col1Width, lineHeight, row[0], "1", "L", false)

		pdf.SetXY(x+col1Width, y)
		pdf.SetFont("Roboto", "", 10)
		pdf.SetFillColor(255, 255, 255)
		pdf.MultiCell(col2Width, lineHeight, row[1], "1", "L", true)

		pdf.SetY(y + height)
	}
}

func tableV(pdf *gofpdf.Fpdf, col [][]string) {
	pageWidth, _ := pdf.GetPageSize()
	marginLeft, _, marginRight, _ := pdf.GetMargins()
	usableWidth := pageWidth - marginLeft - marginRight

	col1Width := usableWidth * 0.35
	colOtherWidth := (usableWidth - col1Width) / 3

	pdf.SetFont("BubisNeue", "", 13)
	pdf.SetFillColor(200, 137, 154)
	pdf.CellFormat(col1Width, 10, col[0][0], "1", 0, "C", true, 0, "")
	for _, header := range col[0][1:] {
		pdf.CellFormat(colOtherWidth, 10, header, "1", 0, "L", true, 0, "")
	}
	pdf.Ln(-1)

	pdf.SetFont("Roboto", "", 10)
	for _, row := range col[1:] {
		pdf.SetFillColor(255, 255, 255)
		pdf.CellFormat(col1Width, 10, row[0], "1", 0, "L", true, 0, "")
		for _, col := range row[1:] {
			pdf.CellFormat(colOtherWidth, 10, col, "1", 0, "L", true, 0, "")
		}
		pdf.Ln(-1)
	}
}

func depScanResult(safeCount int, r *Report, linkMap map[string]int, pdf *gofpdf.Fpdf) {

	vulnCountDep := 0
	vulnPkgCountDep := 0
	for _, result := range r.DepReport.Results {
		if len(result.Vulns) > 0 {
			vulnCountDep++
			vulnPkgCountDep += len(result.Vulns)
		}
	}
	vulnCountDevDep := 0
	vulnPkgCountDevDep := 0
	for _, result := range r.DepDevReport.Results {
		if len(result.Vulns) > 0 {
			vulnCountDevDep++
			vulnPkgCountDevDep += len(result.Vulns)
		}
	}

	vulnerableCount := vulnCountDevDep + vulnCountDep

	if vulnerableCount == 0 {
		return
	}

	pdf.SetFont("BubisNeue", "", 13)
	pdf.CellFormat(pdf.GetStringWidth("Safe packages: ")+5, 8.0, "Safe packages: ", "", 0, "L", false, 0, "")
	pdf.SetFillColor(137, 200, 154)
	pdf.SetTextColor(255, 255, 255)
	pdf.CellFormat(20, 8.0, fmt.Sprintf("%d", safeCount-vulnerableCount), "", 0, "C", true, 0, "")
	pdf.SetTextColor(0, 0, 0)

	pdf.CellFormat(10, 8.0, "", "", 0, "L", false, 0, "")

	pdf.CellFormat(pdf.GetStringWidth("Vulnerable packages:")+5, 8.0, "Vulnerable packages: ", "", 0, "L", false, 0, "")
	pdf.SetFillColor(200, 137, 154)
	pdf.SetTextColor(255, 255, 255)
	pdf.CellFormat(20, 8.0, fmt.Sprintf("%d", vulnerableCount), "", 1, "C", true, 0, "")
	pdf.SetTextColor(0, 0, 0)

	pdf.Ln(5)
	printVulnsByPackage := func(results []depScanner.Result, pdf *gofpdf.Fpdf) {
		for _, result := range results {
			if len(result.Vulns) == 0 {
				continue
			}

			// Dynamic width + Link mapping
			maxWidth := 0.0
			for _, vuln := range result.Vulns {
				linkMap[vuln.Aliases[0]] = pdf.AddLink()
				id := strings.Join(vuln.Aliases, ", ")
				w := pdf.GetStringWidth(id)
				if w > maxWidth {
					maxWidth = w
				}
			}
			maxWidth += 8

			pdf.SetFont("BubisNeue", "", 14)
			pkgTitle := fmt.Sprintf("Package: %s (%d vulnerabilities)", result.PackageName, len(result.Vulns))
			pdf.SetFillColor(138, 41, 84)
			pdf.SetTextColor(255, 255, 255)
			pdf.CellFormat(0, 8, pkgTitle, "1", 1, "L", true, 0, "")

			pdf.SetFont("BubisNeue", "", 13)
			pdf.SetFillColor(200, 137, 154)
			pdf.SetTextColor(0, 0, 0)
			pdf.CellFormat(maxWidth, 8, "Vulnerability ID", "1", 0, "C", true, 0, "")
			pdf.CellFormat(0, 8, "Summary", "1", 1, "C", true, 0, "")

			pdf.SetFont("Roboto", "", 10)
			for _, vuln := range result.Vulns {
				id := strings.Join(vuln.Aliases, ", ")
				pdf.SetTextColor(0, 0, 255)
				pdf.CellFormat(maxWidth, 8, id, "1", 0, "L", false, linkMap[vuln.Aliases[0]], "")
				pdf.SetTextColor(0, 0, 0)
				pdf.MultiCell(0, 8, vuln.Summary, "1", "L", false)
			}

			pdf.Ln(5)
		}

	}

	printVulnsByPackage(r.DepReport.Results, pdf)
	printVulnsByPackage(r.DepDevReport.Results, pdf)

}

func codeScanResult(r *Report, linkMap map[string]int, pdf *gofpdf.Fpdf) {
	if r.CodeReport == nil {
		pdf.SetFont("Roboto", "", 10)
		pdf.CellFormat(0, 0, "No code scan data available.", "", 1, "L", false, 0, "")
		return
	}

	totalVulns := countCodeVulnerabilities(r.CodeReport)
	if totalVulns == 0 {
		pdf.SetFont("Roboto", "", 10)
		pdf.CellFormat(0, 0, "No code vulnerabilities found.", "", 1, "L", false, 0, "")
		return
	}

	pdf.AddPage()
	heading2("Code Scan", pdf)
	pdf.SetY(pdf.GetY() + line)

	pdf.SetFont("BubisNeue", "", 13)
	pdf.CellFormat(pdf.GetStringWidth("Total vulnerabilities found: ")+5, 8.0, "Total vulnerabilities found: ", "", 0, "L", false, 0, "")
	pdf.SetFillColor(200, 137, 154)
	pdf.SetTextColor(255, 255, 255)
	pdf.CellFormat(20, 8.0, fmt.Sprintf("%d", totalVulns), "", 1, "C", true, 0, "")
	pdf.SetTextColor(0, 0, 0)

	pdf.Ln(5)

	pageWidth, _ := pdf.GetPageSize()
	marginLeft, _, marginRight, _ := pdf.GetMargins()
	usableWidth := pageWidth - marginLeft - marginRight

	pathWidth := usableWidth * 0.8
	lineWidth := usableWidth * 0.2
	lineHeight := 6.0

	vulnTypes := getCodeVulnTypes(r.CodeReport)

	for _, vulnType := range vulnTypes {
		if len(vulnType.vulns) == 0 {
			continue
		}

		if vulnType.isCritical {
			pdf.SetFillColor(180, 50, 50)
		} else {
			pdf.SetFillColor(138, 41, 84)
		}

		pdf.SetFont("BubisNeue", "", 14)
		typeTitle := fmt.Sprintf("%s (%d issues)", vulnType.name, len(vulnType.vulns))
		pdf.SetTextColor(255, 255, 255)
		pdf.CellFormat(0, 8, typeTitle, "1", 1, "L", true, 0, "")

		pdf.SetFont("BubisNeue", "", 11)
		pdf.SetFillColor(200, 137, 154)
		pdf.SetTextColor(0, 0, 0)
		pdf.CellFormat(pathWidth, 8, "File Path", "1", 0, "C", true, 0, "")
		pdf.CellFormat(lineWidth, 8, "Line", "1", 1, "C", true, 0, "")

		pdf.SetFont("Roboto", "", 9)
		for _, vuln := range vulnType.vulns {
			cleanPath := strings.TrimPrefix(vuln.Path, "tmp/")
			vulnID := fmt.Sprintf("%s:L%d", cleanPath, vuln.Line)

			// Create link and store it
			linkMap[vulnID] = pdf.AddLink()

			// Calculate dynamic height based on file path wrapping
			pathLines := pdf.SplitText(cleanPath, pathWidth)
			height := float64(len(pathLines)) * lineHeight

			y := pdf.GetY()
			x := pdf.GetX()

			// File path cell with wrapping and link
			pdf.SetXY(x, y)
			pdf.SetFillColor(255, 255, 255)
			pdf.SetTextColor(0, 0, 255)

			// Split the MultiCell into lines and add links to each line
			for i, line := range pathLines {
				if i == 0 {
					// First line gets the link
					pdf.CellFormat(pathWidth, lineHeight, line, "1", 1, "L", true, linkMap[vulnID], "")
				} else {
					// Subsequent lines without links
					pdf.SetX(x)
					pdf.CellFormat(pathWidth, lineHeight, line, "1", 1, "L", true, 0, "")
				}
			}

			// Line number cell (fixed height) with link
			pdf.SetXY(x+pathWidth, y)
			pdf.CellFormat(lineWidth, height, strconv.Itoa(vuln.Line), "1", 0, "C", false, linkMap[vulnID], "")
			pdf.SetTextColor(0, 0, 0)

			pdf.SetY(y + height)
		}

		pdf.Ln(5)
	}
}

func codeVulnScanDetails(linkMap map[string]int, r *Report, pdf *gofpdf.Fpdf) {
	pageWidth, _ := pdf.GetPageSize()
	marginLeft, _, marginRight, _ := pdf.GetMargins()
	usableWidth := pageWidth - marginLeft - marginRight
	vulnTypes := getCodeVulnTypes(r.CodeReport)

	for _, vulnType := range vulnTypes {
		if len(vulnType.vulns) == 0 {
			continue
		}
		pdf.SetY(pdf.GetY() + line)

		for _, vuln := range vulnType.vulns {
			cleanPath := strings.TrimPrefix(vuln.Path, "tmp/")
			vulnID := fmt.Sprintf("%s:L%d", cleanPath, vuln.Line)

			heading3(vulnType.name, pdf)
			pdf.SetY(pdf.GetY() + smLine)

			if linkID, exists := linkMap[vulnID]; exists {
				pdf.SetLink(linkID, 0, pdf.PageNo())
			}

			pdf.SetFont("Roboto", "", 10)
			summary := fmt.Sprintf("%s vulnerability found in %s at line %d.", vuln.Type, cleanPath, vuln.Line)
			pdf.MultiCell(usableWidth, 6, summary, "", "L", false)
			pdf.SetY(pdf.GetY() + smLine)

			pdf.SetFont("BubisNeue", "", 13)
			pdf.CellFormat(0, 8, "Details", "1", 1, "C", false, 0, "")
			pdf.SetY(pdf.GetY() + smLine)

			pdf.SetFont("Roboto", "", 10)
			pdf.MultiCell(usableWidth, 6, "Vulnerable code:", "", "L", false)
			pdf.SetY(pdf.GetY() + 2)

			pdf.SetFont("Courier", "", 9)
			pdf.SetFillColor(245, 245, 245)
			pdf.MultiCell(usableWidth, 5, vuln.Content, "1", "L", true)
			pdf.SetY(pdf.GetY() + bgLine) // Added proper spacing after each vulnerability
		}
	}
}

func getCodeVulnTypes(report *codeScanner.CodeScanReport) []vulnTypeConfig {
	return []vulnTypeConfig{
		{"Remote Code Execution (RCE)", report.RCE, true},
		{"Child Process Execution", report.ChildProcess, true},
		{"VM Module Usage", report.VmModule, true},
		{"Function Constructor Usage", report.FunctionConstructor, true},
		{"Hardcoded Secrets", report.HardcodedSecrets, true},
		{"AWS Keys Exposure", report.AWSKeys, true},
		{"JWT Secrets Exposure", report.JWTSecrets, true},
		{"Database URL Exposure", report.DBUrl, true},
		{"Comments Secrets", report.CommentsSecrets, true},
		{"API Key Exposure", report.ApiKey, true},
		{"Cross-Site Scripting (XSS)", append(report.DSetHTML, append(report.EventHandlers, report.JavaScriptURLs...)...), false},
		{"React Security Issues", append(report.ReactRefsBypass, append(report.NextJSScriptBypass, report.NextJSHeadBypass...)...), false},
		{"Server-Side Rendering Issues", append(report.ServerSideBypass, report.NextJSMiddleware...), false},
		{"Dynamic Imports", report.DynamicImports, false},
		{"CORS Issues", append(report.CORS, report.CorsCredentials...), false},
		{"HTTP Methods", report.Methods, false},
	}
}

func countCodeVulnerabilities(report *codeScanner.CodeScanReport) int {
	return len(report.Methods) + len(report.CORS) + len(report.CorsCredentials) +
		len(report.RCE) + len(report.ApiKey) + len(report.CommentsSecrets) +
		len(report.FunctionConstructor) + len(report.VmModule) + len(report.HardcodedSecrets) +
		len(report.AWSKeys) + len(report.JWTSecrets) + len(report.DBUrl) +
		len(report.ChildProcess) + len(report.DSetHTML) + len(report.ReactRefsBypass) +
		len(report.NextJSScriptBypass) + len(report.NextJSHeadBypass) + len(report.DynamicImports) +
		len(report.EventHandlers) + len(report.JavaScriptURLs) + len(report.ServerSideBypass) +
		len(report.NextJSMiddleware)
}

func vulnScanDetails(linkMap map[string]int, r *Report, pdf *gofpdf.Fpdf) {
	pageWidth, _ := pdf.GetPageSize()
	marginLeft, _, marginRight, _ := pdf.GetMargins()
	usableWidth := pageWidth - marginLeft - marginRight
	printVulnsDetail := func(results []depScanner.Result, pdf *gofpdf.Fpdf) {
		for _, result := range results {
			if len(result.Vulns) == 0 {
				continue
			}
			pdf.AddPage()

			heading2(result.PackageName, pdf)
			pdf.SetY(pdf.GetY() + line)

			for i, vuln := range result.Vulns {
				if i != 0 {
					pdf.AddPage()
				}
				heading3(vuln.Aliases[0], pdf)
				pdf.SetY(pdf.GetY() + smLine)
				pdf.SetFont("Roboto", "", 10)
				pdf.SetLink(linkMap[vuln.Aliases[0]], 0, pdf.PageNo())
				pdf.MultiCell(usableWidth, 6, fmt.Sprintf("%s.", vuln.Summary), "", "L", false)
				pdf.SetY(pdf.GetY() + smLine)
				pdf.SetFont("BubisNeue", "", 13)
				pdf.CellFormat(0, 8, "Details", "1", 1, "C", false, 0, "")
				pdf.SetY(pdf.GetY() + smLine)
				pdf.SetFont("Roboto", "", 10)
				renderMarkdown(pdf, vuln.Details, usableWidth)
			}

		}

	}

	printVulnsDetail(r.DepReport.Results, pdf)
	printVulnsDetail(r.DepDevReport.Results, pdf)
}

func renderMarkdown(pdf *gofpdf.Fpdf, text string, usableWidth float64) {
	lines := strings.Split(text, "\n")

	isCodeBlock := false
	var codeBuffer []string

	// Rules to parse
	headerRegex := regexp.MustCompile(`^(#{1,6})\s*(.*)`)
	boldRegex := regexp.MustCompile(`\*\*(.*?)\*\*`)
	italicRegex := regexp.MustCompile(`\*(.*?)\*`)
	linkRegex := regexp.MustCompile(`\[(.*?)\]\((.*?)\)`)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "```") {
			isCodeBlock = !isCodeBlock
			if !isCodeBlock {

				codeText := strings.Join(codeBuffer, "\n")
				pdf.SetFont("Courier", "", 9)
				pdf.SetFillColor(230, 230, 230)
				pdf.MultiCell(usableWidth, 5, codeText, "", "L", true)
				pdf.Ln(2)
				codeBuffer = nil
			}
			continue
		}
		if isCodeBlock {
			codeBuffer = append(codeBuffer, line)
			continue
		}

		if matches := headerRegex.FindStringSubmatch(trimmed); matches != nil {
			pdf.SetFont("BubisNeue", "", 13)
			pdf.MultiCell(usableWidth, 6, matches[2], "", "L", false)
			pdf.Ln(1)
			continue
		}

		trimmed = linkRegex.ReplaceAllString(trimmed, "$1 ($2)")
		trimmed = boldRegex.ReplaceAllString(trimmed, "$1")
		trimmed = italicRegex.ReplaceAllString(trimmed, "$1")

		pdf.SetFont("Roboto", "", 10)
		pdf.MultiCell(usableWidth, 5, trimmed, "", "L", false)
		pdf.Ln(1)
	}
}
