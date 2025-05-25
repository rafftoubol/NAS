package report

import (
	"attack-surface/src/scanner/codeScanner"
	"attack-surface/src/scanner/depScanner"
	"attack-surface/src/utils"
	"attack-surface/src/utils/config"
	"fmt"
	"os"
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

	logo := `
 ________   ________  ________      
|\   ___  \|\   __  \|\   ____\     
\ \  \\ \  \ \  \|\  \ \  \___|_    
 \ \  \\ \  \ \   __  \ \_____  \   
  \ \  \\ \  \ \  \ \  \|____|\  \  
   \ \__\\ \__\ \__\ \__\____\_\  \ 
    \|__| \|__|\|__|\|__|\_________\
                        \|_________|`
	lines := strings.Split(strings.Trim(logo, "\n "), "\n")
	lineHeight := 0.9

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
	depCount := 0
	for range n.Dependencies {
		depCount++
	}
	devDepCount := 0
	for range n.DevDependencies {
		devDepCount++
	}

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
	pdf.SetDrawColor(139, 74, 105)

	pdf.SetLineWidth(0.6)
	pdf.Line(10, pdf.GetY()+5, pageWidth-10, pdf.GetY()+5)
	pdf.SetY(pdf.GetY() + bgLine + 2)
	heading2("NAS Scan Result", pdf)

	pdf.SetY(pdf.GetY() + bgLine)
	heading3("DepScan Result", pdf)

	pdf.SetY(pdf.GetY() + bgLine)
	heading3("CodeScan Result", pdf)
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
	pdf.SetFont("BubisNeue", "", 24)
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
