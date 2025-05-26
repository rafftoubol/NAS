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
		{"Project Path", "Ouputh Path", "Code Scanner", "Dependencies Scanner"},
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
	heading2("Code Scan", pdf)
	pdf.SetY(pdf.GetY() + line)
	if c.CodeScan {
		codeScanResult(r, pdf)
	} else {
		pdf.SetFont("Roboto", "", 10)
		pdf.CellFormat(0, 0, "Code Scan is Skipped (Disabled).", "", 1, "L", false, 0, "")
	}

	if c.DependenciesScan {
		// Third Page
		pdf.AddPage()

		pdf.SetFont("BubisNeue", "", 36)
		pdf.CellFormat(0, pageHeight/2+18, "Vulnerabilities Details", "", 1, "C", false, 0, "")
		vulnScanDetails(linkMap, r, pdf)
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

func codeScanResult(r *Report, pdf *gofpdf.Fpdf) {
	// To work on
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
