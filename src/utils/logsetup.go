// This file creates a log file
// Returns either error or a pointer to fullpath, and the Logger
// Captial used not camel case so the logger and the full path is in global namespace

package utils

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// SetupLog, add validation and test
func SetupLog(logPath string, logName string) (*log.Logger, error) {

	// If no / at the end of the path provide it
	if !strings.HasSuffix(logPath, "/") {
		logPath = logPath + "/" + logName
	} else {
		logPath = logPath + logName
	}
	// Create the log directory if it doesn't exist
	err := os.MkdirAll(logPath, os.ModePerm)
	if err != nil {

		return nil, fmt.Errorf("error creating log directory: %w", err)
	}
	// Create the log file
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("error creating log file: %v", err)
	}

	// Create a new logger
	Logger := log.New(logFile, "", log.LstdFlags)
	Logger.Println("Log file created at", logPath)
	fmt.Println("Log file created at", time.Now())
	return Logger, nil
}
