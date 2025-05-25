package report

import (
	"attack-surface/src/scanner/codeScanner"
	"attack-surface/src/scanner/depScanner"
	"attack-surface/src/utils"
	"fmt"
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

func GeneratePDF(r *Report, n *utils.Next, outputPath string) error {
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

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AliasNbPages("")
	pdf.AddUTF8Font("BubisNeue", "", "font/BebasNeue-Regular.ttf")
	pdf.AddUTF8Font("Roboto", "", "font/Roboto-Regular.ttf")
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
		pdf.SetFont("Apple", "I", 10)
		pdf.CellFormat(0, 10, time.Now().Format("02/01/2006 15:04"), "", 0, "L", false, 0, "")
		pageInfo := fmt.Sprintf("Page %d of {nb}", pdf.PageNo())
		pdf.CellFormat(0, 10, pageInfo, "", 0, "R", false, 0, "")
	})
	pdf.AddPage()
	heading1("Next.js Project Summary", pdf)

	heading2("Project Summary", pdf)
	pdf.SetY(65)
	heading3("Project Summary", pdf)
	pdf.AddPage()
	pdf.SetFont("BubisNeue", "", 12)
	pdf.MultiCell(0, 10, "Seconda pagina del report con lo stesso header in alto.", "", "L", false)

	if err := pdf.OutputFileAndClose("generated.pdf"); err != nil {
		return err
	}
	input := []string{"src/utils/report/cover.pdf", "generated.pdf"}
	if err := api.MergeCreateFile(input, "report.pdf", false, nil); err != nil {
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
