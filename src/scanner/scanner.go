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
	"github.com/sirupsen/logrus"
)

type Scanner struct {
	config *config.Config
	report *Result
}

type Result struct {
	codeReport   *codeScanner.CodeScanReport
	depReport    *depScanner.Response // Temporary -> Would Become Vuln
	depDevReport *depScanner.Response // Temporary -> Would Become Vuln
}

func NewScanner(config *config.Config) *Scanner {
	return &Scanner{
		config: config,
	}
}

func (b *Scanner) Scan() error {
	b.report = &Result{}
	logrus.Debugf("Current Scan Option: ProjectPath: %s, OutputPath: %s, API Scan Enabled: %v, Dependencies Scan Enabled: %v",
		b.config.ProjectPath, b.config.OutputPath, *b.config.CodeScan, *b.config.DependenciesScan)

	// Expand with future cong Options
	if b.config.DependenciesScan != nil && *b.config.DependenciesScan {
		logrus.Info("Dependencies Scan Enabled")

		// Parse Next.js -> Validate if is a Next.js Repository
		next, err := utils.InitNext(b.config.ProjectPath)
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

		b.report.depReport = depReport
		b.report.depDevReport = depDevReport

	} else {
		logrus.Info("Dependencies Scan is Skipped (Disabled)")
	}

	if b.config.CodeScan != nil && *b.config.CodeScan {

		// Run scanner code
		codeReport, err := codeScanner.CodeScanner(b.config.ProjectPath)
		if err != nil {
			return err
		}

		// Check if b.report has been created
		if b.report == nil {
			b.report = &Result{}
		}

		b.report.codeReport = codeReport

		logrus.Info("Code Scan Enabled")
	} else {
		logrus.Info("Code Scan is Skipped (Disabled)")
	}

	logrus.Infoln("Scan Successful")

	b.Print()
	return nil
}

func (b *Scanner) Print() {
	// Temporary -> Logic to print file will be here.
	// Now just print out Vuln found
	if b.report == nil {
		return
	}

	// Print out devReport
	for i, result := range b.report.depReport.Results {
		if len(result.Vulns) > 0 {
			logrus.Infof("Package %d found with %d vulnerabilitys:", i, len(result.Vulns))
			for _, vuln := range result.Vulns {
				logrus.Infof("- ID: %s, Modified: %s", vuln.ID, vuln.Modified)
			}
		}
	}
	// Print out devDevReport
	for i, result := range b.report.depDevReport.Results {
		if len(result.Vulns) > 0 {
			logrus.Infof("Package %d found with %d vulnerabilitys:", i, len(result.Vulns))
			for _, vuln := range result.Vulns {
				logrus.Infof("- ID: %s, Modified: %s", vuln.ID, vuln.Modified)
			}
		}
	}

	if len(b.report.codeReport.Methods) > 0 || len(b.report.codeReport.CORS) > 0 || len(b.report.codeReport.RCE) > 0 ||
		len(b.report.codeReport.ApiKey) > 0 || len(b.report.codeReport.CoomentsSecrets) > 0 {
		logrus.Println("Methods ", b.report.codeReport.Methods)
		logrus.Println("CORS ", b.report.codeReport.CORS)
		logrus.Println("RCE ", b.report.codeReport.RCE)
		logrus.Println("ApiKey ", b.report.codeReport.ApiKey)
		logrus.Println("CoomentsSecrets ", b.report.codeReport.CoomentsSecrets)
	} else {
		logrus.Println("Code Scan: No vulnerabilities found")
	}

	// Here put output logic
	return
}
