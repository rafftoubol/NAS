/*
This file contains the declaration of the main Scanner. It include all our scanning methods.
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
	codeReport codeScanner.CodeScanReport
}

func NewScanner(config *config.Config) *Scanner {
	return &Scanner{
		config: config,
	}
}

func (b *Scanner) Scan() error {

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
		if err := depScanner.DepScanner(next.Dependencies); err != nil {
			logrus.Info("Dependencies Scan Successful")
		}

		// Scan DevDependencies
		if err := depScanner.DepScanner(next.DevDependencies); err != nil {
			logrus.Info("Dependencies Scan Successful")
		}

	} else {
		logrus.Info("Dependencies Scan is Skipped (Disabled)")
	}

	if b.config.CodeScan != nil && *b.config.CodeScan {
		logrus.Info("Code Scan Enabled")
	} else {
		logrus.Info("Code Scan is Skipped (Disabled)")
	}

	return nil
}

func (b *Scanner) Print() {
	return
}
