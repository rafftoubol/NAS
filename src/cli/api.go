package cli

import (
	"attack-surface/src/api"
	"attack-surface/src/output"
	"attack-surface/src/scanner"
	config "attack-surface/src/utils"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"time"
)

var (
	outputPath   string
	exportFlag   bool
	exportFormat string
)

// Define package-level constants
const (
	FormatPDF  = "pdf"
	FormatJSON = "json"
)

// Custom error types
type UnsupportedFormatError struct {
	Format string
}

func (e *UnsupportedFormatError) Error() string {
	return fmt.Sprintf("unsupported export format: %s (use '%s' or '%s')", e.Format, FormatPDF, FormatJSON)
}

var apiCmd = &cobra.Command{
	Use:   "api [project_path]",
	Short: "Discovers API routes in the Next.js project",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			logrus.Fatalln("Missing project path argument. Please provide the project path as an argument.")
		}

		config, _ := config.NewConfigBuilder().
			DefProjectPath(args[0]).
			DefApiScan(true).
			WithDefaults().
			Build()

		if err := config.Validate(); err != nil {
			logrus.Fatalln(err)
		}

		if err := config.LoadConfigRepo(); err != nil {
			logrus.Fatalln(err)
		}

		// Run the API analysis
		apiResults := api.DiscoverAPIRoutes(config.ProjectPath)
		if apiResults == nil {
			logrus.Fatalln("Failed to analyze project")
		}

		// Run the dependency scanner
		//TODO: Fix how scanner Dependency works so as to run it along with the api scanner @menny & @raph
		dependencyResults, err := scanner.Scanner(config.Dependencies)
		if err != nil {
			logrus.Fatalln("Failed to scan dependencies:", err)
		}

		// Combine results
		combinedResults := &output.CombinedResults{
			APIs:         apiResults,
			Dependencies: dependencyResults,
		}

		if exportFlag && exportFormat == FormatPDF {
			if err := handleExport(combinedResults, exportFormat); err != nil {
				logrus.Fatalln("Export failed:", err)
			}
		} else {
			printToTerminal(combinedResults)
		}

	},
}

func init() {
	apiCmd.Flags().StringVarP(&outputPath, "output", "o", ".", "Output path for the results")
	apiCmd.Flags().BoolVarP(&exportFlag, "export", "e", false, "Export results to a file")
	apiCmd.Flags().StringVar(&exportFormat, "format", "", "Export format (pdf|json)")
	rootCmd.AddCommand(apiCmd)
}

func printToTerminal(results *output.CombinedResults) {
	fmt.Println("\n🔍 API Scan Results:")
	// Print API results
	printAPIResults(results.APIs)

	fmt.Println("\n📦 Dependency Scan Results:")
	// Print dependency results
	if results.Dependencies != nil {
		for _, v := range results.Dependencies.Vulnerabilities {
			fmt.Printf("⚠️ [%s] %s@%s\n\tSeverity: %s\n\tDetails: %s\n",
				v.PackageName, v.PackageName, v.Version, v.Severity, v.Details)
		}
	}
}

func printAPIResults(results *api.APIs) {
	fmt.Println("🔍 Scan Results:")

	for _, m := range results.Methods {
		fmt.Printf("⚠️ [Method] %s found in %s at line %d\n \t[Content] %s\n",
			m.Type, m.Path, m.Line, m.Content)
	}

	for _, m := range results.RCE {
		fmt.Printf("🚨 [Vulnerability] type %s found in %s at line %d\n \t[Content] %s\n",
			m.Type, m.Path, m.Line, m.Content)
	}

	for _, m := range results.CORS {
		fmt.Printf("🚨 [Vulnerability] type %s found in %s at line %d\n \t[Content] %s\n",
			m.Type, m.Path, m.Line, m.Content)
	}

	for _, m := range results.ApiKey {
		fmt.Printf("🚨 [Vulnerability] type %s found in %s at line %d\n \t[Content] %s\n",
			m.Type, m.Path, m.Line, m.Content)
	}

	for _, m := range results.CoomentsSecrets {
		fmt.Printf("🚨 [Vulnerability] type %s found in %s at line %d\n \t[Content] %s\n",
			m.Type, m.Path, m.Line, m.Content)
	}
}

func handleExport(results *output.CombinedResults, format string) error {
	if format != FormatPDF && format != FormatJSON {
		return &UnsupportedFormatError{Format: format}
	}

	// Create reports directory if it doesn't exist
	reportsPath := filepath.Join(".", "reports")
	if err := os.MkdirAll(reportsPath, 0755); err != nil {
		return fmt.Errorf("failed to create reports directory: %w", err)
	}

	switch format {
	case FormatPDF:
		return handlePDFExport(results, reportsPath)
	case FormatJSON:
		return fmt.Errorf("JSON export format is not implemented yet")
	}

	return nil
}

func handlePDFExport(results *output.CombinedResults, reportsPath string) error {
	filename := filepath.Join(reportsPath,
		fmt.Sprintf("security_analysis_%s.pdf", time.Now().Format("20060102_150405")))

	exporter := output.NewPDFExporter(results)
	if err := exporter.Export(filename); err != nil {
		return fmt.Errorf("failed to export to PDF: %w", err)
	}

	printReportInfo(filename)
	return nil
}

func printReportInfo(filename string) {
	fmt.Println("\n📄 Report Generation Complete")
	fmt.Printf("📁 Report saved to: %s\n", filename)
	fmt.Println("📌 To open the report:")
	fmt.Printf("   Linux: xdg-open %s\n", filename)
	fmt.Printf("   macOS: open %s\n", filename)
}
