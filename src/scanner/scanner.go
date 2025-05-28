/*
This file contains the declaration of the main DepScanner. It include all our scanning methods.
Our aim is to provide a maintanable way to add feature to this scanner. This scanner can be easily expanded with new
functions.

*/

package scanner

import (
	"attack-surface/src/scanner/codeScanner"
	"attack-surface/src/scanner/depScanner"
	"attack-surface/src/utils"
	"attack-surface/src/utils/config"
	"attack-surface/src/utils/report"
	"fmt"
	"reflect"
	"strings"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
)

type Scanner struct {
	config *config.Config
	report *report.Report
	next   *utils.Next
}

func NewScanner(config *config.Config) (*Scanner, error) {
	// Parse Next.js -> Validate if is a Next.js Repository

	next, err := utils.InitNext(config.ProjectPath)
	if err != nil {
		return nil, err
	}

	return &Scanner{
		config: config,
		next:   next,
	}, nil
}

func (b *Scanner) Scan() error {
	// To prevent segmentation fault
	b.report = &report.Report{
		CodeReport:   &codeScanner.CodeScanReport{},
		DepReport:    &depScanner.Response{},
		DepDevReport: &depScanner.Response{},
	}

	logrus.Debugf("Current Scan Option: WithProjectPath: %s, OutputPath: %s, API Scan Enabled: %v, Dependencies Scan Enabled: %v",
		b.config.ProjectPath, b.config.OutputPath, b.config.CodeScan, b.config.DependenciesScan)

	// Expand with future cong Options
	if b.config.DependenciesScan {

		// Run scanner Dependencies
		logrus.Infof("%s ", color.New(color.FgCyan, color.Bold).Sprint("Scanning Dependencies"))
		depReport, err := depScanner.DepScanner(b.next.Dependencies)
		if err != nil {
			return err
		}

		// Run scanner DevDependencies
		logrus.Infof("%s ", color.New(color.FgCyan, color.Bold).Sprint("Scanning devDependencies"))
		depDevReport, err := depScanner.DepScanner(b.next.DevDependencies)

		if err != nil {
			return err
		}

		if b.report == nil {
			b.report = &report.Report{}
		}
		b.report.DepReport = depReport
		b.report.DepDevReport = depDevReport

	} else {
		logrus.Info("Dependencies Scan is Skipped (Disabled)")
	}

	if b.config.CodeScan {
		logrus.Infof("%s ", color.New(color.FgCyan, color.Bold).Sprint("Scanning Code"))

		// Run scanner code
		codeReport, err := codeScanner.CodeScanner(b.config.ProjectPath)
		if err != nil {
			return err
		}

		b.report.CodeReport = codeReport

		// Draft, change how we check if is empty
		if len(b.report.CodeReport.Methods) == 0 || len(b.report.CodeReport.CORS) == 0 || len(b.report.CodeReport.RCE) == 0 ||
			len(b.report.CodeReport.ApiKey) == 0 || len(b.report.CodeReport.CommentsSecrets) == 0 {
			logrus.Info("Code Scan found no Vulnerabilities")
		}
	} else {
		logrus.Infoln("Code Scan is Skipped (Disabled)")
	}

	logrus.Infoln("Scan terminated successfully")

	if err := b.Print(); err != nil {
		return err
	}
	logrus.Infoln("Report generated successfully in", b.config.OutputPath)

	return nil
}

// POC Function to print the report.
func (b *Scanner) Print() error {
	logrus.Infof("%s", color.New(color.FgMagenta, color.Bold).Sprint("Vulnerability Report "))

	if b.report == nil {
		return fmt.Errorf("No report found")
	}

	// Print out devReport
	for _, result := range b.report.DepReport.Results {
		if len(result.Vulns) > 0 {
			logrus.Infof("Package %s found with %d vulnerabilitys", result.PackageName, len(result.Vulns))
			for _, vuln := range result.Vulns {
				logrus.Debugf("- ID: %-35s   %s", strings.Join(vuln.Aliases, " "), vuln.Summary)
			}
		}
	}
	// Print out devDevReport
	for _, result := range b.report.DepDevReport.Results {
		if len(result.Vulns) > 0 {
			logrus.Infof("Package %s found with %d vulnerabilitys", result.PackageName, len(result.Vulns))
			for _, vuln := range result.Vulns {
				logrus.Debugf("- ID: %-35s   %s", strings.Join(vuln.Aliases, " "), vuln.Summary)
			}
		}
	}

	/*
		Everything from here till the final return is just for printing the results of the code scanner!!!!!
	*/
	reportValue := reflect.ValueOf(b.report.CodeReport).Elem()
	reportType := reflect.TypeOf(b.report.CodeReport).Elem()
	/*
	   Basically all we are doing is checking if debugging is set, if it is then we are creating a table of elements and
	   flattening it into one logrus message which shows the detailed information for each element from every field,
	   we also trim off all the json things like {} "" and character escaping.

	   if debugging is not set we just do a simple check for how many items in each element.
	*/
	if logrus.GetLevel() >= logrus.DebugLevel {
		for i := 0; i < reportValue.NumField(); i++ {
			// Assign some local variables for stuff
			field := reportValue.Field(i)
			fieldType := reportType.Field(i)
			displayName := fieldType.Tag.Get("display")

			if field.Kind() == reflect.Slice && field.Len() > 0 {

				// Create a table for verbose printing

				title := fmt.Sprintf(" %s (%d found) ", displayName, field.Len())
				tableWidth := 60 // Fixed width for consistency
				var tableOutput strings.Builder
				tableOutput.WriteString(strings.Repeat("=", tableWidth) + "\n")
				padding := (tableWidth - len(title)) / 2
				tableOutput.WriteString("=" + strings.Repeat(" ", padding) + title + strings.Repeat(" ", tableWidth-padding-len(title)-2) + "=\n")
				tableOutput.WriteString(strings.Repeat("=", tableWidth) + "\n")

				// Add all vulnerabilities
				for j := 0; j < field.Len(); j++ {
					item := field.Index(j).Interface()

					tableOutput.WriteString(fmt.Sprintf("  [%d]\n", j+1))

					// Extract clean values based on type
					switch v := item.(type) {
					case string:
						tableOutput.WriteString(fmt.Sprintf("    %s\n", v))
					case map[string]interface{}:
						for key, value := range v {
							valueStr := fmt.Sprintf("%v", value)
							valueStr = strings.ReplaceAll(valueStr, "\\u003c", "<")
							valueStr = strings.ReplaceAll(valueStr, "\\u003e", ">")
							valueStr = strings.ReplaceAll(valueStr, "\\", "")
							tableOutput.WriteString(fmt.Sprintf("    %s: %s\n", key, valueStr))
						}
					default:
						itemValue := reflect.ValueOf(item)
						itemType := reflect.TypeOf(item)

						if itemValue.Kind() == reflect.Struct {
							for k := 0; k < itemValue.NumField(); k++ {
								fieldVal := itemValue.Field(k)
								fieldName := itemType.Field(k).Name

								valueStr := fmt.Sprintf("%v", fieldVal.Interface())
								valueStr = strings.ReplaceAll(valueStr, "\\u003c", "<")
								valueStr = strings.ReplaceAll(valueStr, "\\u003e", ">")
								valueStr = strings.ReplaceAll(valueStr, "\\", "")

								tableOutput.WriteString(fmt.Sprintf("    %s: %s\n", fieldName, valueStr))
							}
						}
					}
				}

				// Bottom border
				tableOutput.WriteString(strings.Repeat("=", tableWidth) + "\n\n")

				// Print the entire table as one logrus message
				logrus.Info("\n" + strings.TrimSuffix(tableOutput.String(), "\n"))
			}
		}
	} else {
		/*
			This is for the normal output where we just print the total number of vulnerabilities for each category
			of the struct
		*/
		totalVulns := 0

		for i := 0; i < reportValue.NumField(); i++ {
			field := reportValue.Field(i)
			fieldType := reportType.Field(i)

			// Get the display name from tag, fallback to field name
			displayName := fieldType.Tag.Get("display")
			if displayName == "" {
				displayName = fieldType.Name
			}

			if field.Kind() == reflect.Slice {
				count := field.Len()
				if count > 0 {
					logrus.Infof("%s: %d", displayName, count)
					totalVulns += count
				}
			}
		}

	}

	return report.GeneratePDF(b.report, b.next, b.config)
}
