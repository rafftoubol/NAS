/*
The purpose of this file is to implement a checker where on start-up we check a couple of things on cve_cache.json,
A) if it exists
B) if we can open it
C) if the last updated date is more than 24 hrs
--> A "no" result to any of those should result in running fetchCVE again updating the whole database

This functionality was written in the fetchCVE file however the file was getting [in my opinion] too big so for
ease of reading, understanding and separation of duties i've broken it out into this file, please provide feedback
*/

package utils

import (
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"os"
	"time"
)

const databasePath = "./tmp/cve/cve_cache.json"
const cveRepo = "https://cve.circl.lu/api/search/vercel/next.js"

/*
Method on the CVEs struct to check the last updated time
PRE: CVE Pointer
POST: Boolean
*/
func (c *CVEs) IsExpired() bool {
	return time.Since(c.LastUpdated) > 24*time.Hour
}

func CVECacheChecker() (*CVEs, error) {
	// Log the start of the check
	logrus.Debug("Checking if CVE database cache exists and is accessible...")
	// A) Check if the database file exists
	_, err := os.Stat(databasePath)
	if err != nil {
		logrus.Errorf("CVE cache file %s does not exist, or is inaccessible: %v", databasePath, err)
		cve, err := FetchCVE(cveRepo)
		if err != nil {
			return nil, err
		}
		return cve, nil
	}
	// B) Check if the file can be opened
	file, err := os.Open(databasePath)
	if err != nil {
		logrus.Errorf("Failed to open CVE database cache file %s: %v", databasePath, err)
		cve, err := FetchCVE(cveRepo)
		if err != nil {
			return nil, err
		}
		return cve, nil
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			logrus.Errorf("Failed to close CVE database cache file %s: %v", databasePath, err)
		}
	}(file)

	// C) Attempt to parse the JSON file into the CVEs structure
	var Cves CVEs
	if err := json.NewDecoder(file).Decode(&Cves); err != nil {
		logrus.Errorf("CVE cache file %s is corrupt or unreadable: %v", databasePath, err)
		return nil, fmt.Errorf("file is corrupt or unreadable: %w", err)
	}
	// C) Check if the DB is older than 24 Hours
	if Cves.IsExpired() {
		logrus.Info("CVE database cache is expired, fetching new data...")
		cve, err := FetchCVE(cveRepo)
		if err != nil {
			return nil, err
		}
		return cve, nil
	}

	logrus.Info("Successfully validated the CVE database cache.")
	return &Cves, nil
}
