// This file contains the declaration of the main Scanner. It include all our scanning methods.

package scanner

import (
	"attack-surface/src/scanner/codeScanner"
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
	if b.config.DependenciesScan != nil && *b.config.DependenciesScan {
		logrus.Info("Dependencies Scan Enabled")
	} else {
		logrus.Info("Dependencies Scan Disabled")
	}

	if b.config.CodeScan != nil && *b.config.CodeScan {
		logrus.Info("Dependencies Scan Enabled")
	} else {
		logrus.Info("Dependencies Scan Disabled")
	}

	return nil
}

func (b *Scanner) Print() {
	return
}
