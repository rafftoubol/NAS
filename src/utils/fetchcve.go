/*
This file fetches CVEs unmarshals them and stores them in json format,
with a CVE struct for each CVE, and a CVEs struct containing all the CVEs,
and a metadata struct for the CVE database.


TO DO: my idea is maybe we have configs where it can be specified, like a check box in the
config file for NIST, SNYK, then we can pass the urls dynamically.

TO DO: Refactor for a goroutine, so we can fetch multiple CVE repos at the same time.

TO DO: Integrate into main.go, and base func call off time of last update.

NOTE: currently just hardcoded to one CVE repo

Preconditions:
  - cveRepo (string): Must be a valid HTTP/HTTPS URL pointing to a JSON endpoint containing CVE data
  - Write permissions must exist for ./tmp/cve directory

Postconditions:
  - Returns a POINTER to CVEs struct containing the parsed vulnerability data
  - Creates/updates a local cache file at ./tmp/cve/cve_cache.json
  - Returns error if any step in the fetch, cache, or parse process fails

The function performs the following operations:
1. Fetches CVE data from the provided repository URL
2. Creates a local cache directory if it doesn't exist
3. Saves the raw JSON response to a cache file
4. Parses the JSON data into a CVEs struct

Return values:
  - *CVEs: Pointer to parsed CVE data structure
  - error: Non-nil if any operation fails
*/

package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// CVEs represents a collection of CVE entries
type CVEs struct {
	LastUpdated time.Time       `json:"lastUpdated"`
	Data        json.RawMessage `json:"data"`
}

func FetchCVE(cveRepo string) (*CVEs, error) {
	resp, err := http.Get(cveRepo)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println(err)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to fetch CVEs: %s ", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Create our final CVEs structure
	Cves := CVEs{
		LastUpdated: time.Now(),
		Data:        body,
	}

	if err != nil {
		return nil, err
	} else {

	}

	// Save to cache
	updatedJSON, err := json.Marshal(Cves)
	if err != nil {
		return nil, err
	}

	err = os.MkdirAll("./tmp/cve", 0755)
	if err != nil {
		return nil, err
	}

	err = os.WriteFile("./tmp/cve/cve_cache.json", updatedJSON, 0644)
	if err != nil {
		return nil, err
	}

	return &Cves, nil
}

func parseTime(timeStr string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, timeStr)
	return t
}
