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
			len(b.report.CodeReport.ApiKey) == 0 || len(b.report.CodeReport.CoomentsSecrets) == 0 {
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

	// Draft, change how we check if is empty and how we print it.
	if len(b.report.CodeReport.Methods) > 0 || len(b.report.CodeReport.CORS) > 0 || len(b.report.CodeReport.RCE) > 0 ||
		len(b.report.CodeReport.ApiKey) > 0 || len(b.report.CodeReport.CoomentsSecrets) > 0 {
		logrus.Infoln("Methods ", b.report.CodeReport.Methods)
		logrus.Infoln("CORS ", b.report.CodeReport.CORS)
		logrus.Infoln("RCE ", b.report.CodeReport.RCE)
		logrus.Infoln("ApiKey ", b.report.CodeReport.ApiKey)
		logrus.Infoln("CoomentsSecrets ", b.report.CodeReport.CoomentsSecrets)
	}

	// Here put report logic
	// Change in the future
	// This control that we have this

	return report.GeneratePDF(b.report, b.next, b.config)
}
