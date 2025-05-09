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
	"github.com/sirupsen/logrus"
)

type Scanner struct {
	config *config.Config
	report *Result
}

type Result struct {
	CodeReport   *codeScanner.CodeScanReport
	DepReport    *depScanner.Response // Temporary -> Would Become Vuln
	DepDevReport *depScanner.Response // Temporary -> Would Become Vuln
}

func NewScanner(config *config.Config) *Scanner {
	return &Scanner{
		config: config,
	}
}

func (b *Scanner) Scan() error {
	b.report = &Result{}
	logrus.Debugf("Current Scan Option: WithProjectPath: %s, OutputPath: %s, API Scan Enabled: %v, Dependencies Scan Enabled: %v",
		b.config.WithProjectPath, b.config.OutputPath, *b.config.CodeScan, *b.config.DependenciesScan)

	// Expand with future cong Options
	if b.config.DependenciesScan != nil && *b.config.DependenciesScan {
		logrus.Info("Dependencies Scan Enabled")

		// Parse Next.js -> Validate if is a Next.js Repository
		next, err := utils.InitNext(b.config.WithProjectPath)
		if err != nil {
			return err
		}
		// Scan Dependencies
		depReport, err := depScanner.DepScanner(next.Dependencies)

		if err != nil {
			return err
		}

		if b.report == nil {
			b.report = &Result{}
		}
		// Scan DevDependencies
		depDevReport, err := depScanner.DepScanner(next.DevDependencies)

		if err != nil {
			return err
		}

		if b.report == nil {
			b.report = &Result{}
		}

		b.report.DepReport = depReport
		b.report.DepDevReport = depDevReport

	} else {
		logrus.Info("Dependencies Scan is Skipped (Disabled)")
	}

	if b.config.CodeScan != nil && *b.config.CodeScan {

		// Run scanner code
		codeReport, err := codeScanner.CodeScanner(b.config.WithProjectPath)
		if err != nil {
			return err
		}

		// Check if b.report has been created
		if b.report == nil {
			b.report = &Result{}
		}

		b.report.CodeReport = codeReport

		logrus.Info("Code Scan Enabled")
	} else {
		logrus.Info("Code Scan is Skipped (Disabled)")
	}

	logrus.Infoln("Scan Successful")
	logrus.Debug("Generating Report")
	if err := b.Print(); err != nil {
		return err
	}
	logrus.Infoln("Report Generated")
	return nil
}

func (b *Scanner) Print() error {
	// Temporary -> Logic to print file will be here.
	// Now just print out Vuln found
	if b.report == nil {
		return fmt.Errorf("No report found")
	}
	if b.config.DependenciesScan != nil && *b.config.DependenciesScan {

		// Print out devReport
		for i, result := range b.report.DepReport.Results {
			if len(result.Vulns) > 0 {
				logrus.Infof("Package %d found with %d vulnerabilitys:", i, len(result.Vulns))
				for _, vuln := range result.Vulns {
					logrus.Infof("- ID: %s, Modified: %s", vuln.ID, vuln.Modified)
				}
			}
		}
		// Print out devDevReport
		for i, result := range b.report.DepDevReport.Results {
			if len(result.Vulns) > 0 {
				logrus.Infof("Package %d found with %d vulnerabilitys:", i, len(result.Vulns))
				for _, vuln := range result.Vulns {
					logrus.Infof("- ID: %s, Modified: %s", vuln.ID, vuln.Modified)
				}
			}
		}
	}
	if b.config.CodeScan != nil && *b.config.CodeScan {
		if len(b.report.CodeReport.Methods) > 0 || len(b.report.CodeReport.CORS) > 0 || len(b.report.CodeReport.RCE) > 0 ||
			len(b.report.CodeReport.ApiKey) > 0 || len(b.report.CodeReport.CoomentsSecrets) > 0 {
			logrus.Println("Methods ", b.report.CodeReport.Methods)
			logrus.Println("CORS ", b.report.CodeReport.CORS)
			logrus.Println("RCE ", b.report.CodeReport.RCE)
			logrus.Println("ApiKey ", b.report.CodeReport.ApiKey)
			logrus.Println("CoomentsSecrets ", b.report.CodeReport.CoomentsSecrets)
		} else {
			logrus.Println("Code Scan: No vulnerabilities found")
		}
	}

	// Here put report logic
	// Change in the future
	// This control that we have this
	if b.config.DependenciesScan != nil && *b.config.DependenciesScan {
		return report.GeneratePDF(b.report.DepReport, b.config.OutputPath)
	}

	return nil
}
