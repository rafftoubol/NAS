// This file creates a log file
// Returns either error or a pointer to fullpath, and the Logger
// Captial used not camel case so the logger and the full path is in global namespace

package utils

import (
	"github.com/sirupsen/logrus"
)

func SetUpLogger(verbose bool) {
	if verbose {
		logrus.SetLevel(logrus.DebugLevel)
		//logFile, err := os.OpenFile("output.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		//if err != nil {
		//	logrus.Warn("Error opening log file: %v", err)
		//}
		//logrus.SetOutput(logFile)
		//fmt.Println("Check file './output.log' for the full output.")
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	logrus.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
		FullTimestamp:   true,
	})

}
