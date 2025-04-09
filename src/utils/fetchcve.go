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

// CVE represents a single Common Vulnerability and Exposure entry
type CVE struct {
	ID              string    `json:"id"`
	SourceID        string    `json:"sourceIdentifier"`
	Published       time.Time `json:"published"`
	LastModified    time.Time `json:"lastModified"`
	VulnStatus      string    `json:"vulnStatus"`
	CVETags         []string  `json:"cveTags"`
	Description     string    `json:"value"` // Will store English description
	BaseScore       float64   `json:"baseScore"`
	BaseSeverity    string    `json:"baseSeverity"`
	VectorString    string    `json:"vectorString"`
	Version         string    `json:"version"`
	AttackVector    string    `json:"attackVector"`
	AttackComplex   string    `json:"attackComplexity"`
	PrivRequired    string    `json:"privilegesRequired"`
	UserInteraction string    `json:"userInteraction"`
	Scope           string    `json:"scope"`
	ConfImpact      string    `json:"confidentialityImpact"`
	IntegImpact     string    `json:"integrityImpact"`
	AvailImpact     string    `json:"availabilityImpact"`
	ExploitScore    float64   `json:"exploitabilityScore"`
	ImpactScore     float64   `json:"impactScore"`
}

// CVEs represents a collection of CVE entries
type CVEs struct {
	LastUpdated     time.Time `json:"lastUpdated"`
	Vulnerabilities []CVE     `json:"vulnerabilities"`
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
		return nil, fmt.Errorf("failed to fetch CVEs: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// First unmarshal into a temporary structure to handle the nested JSON
	var rawData map[string][][]json.RawMessage
	err = json.Unmarshal(body, &rawData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse raw CVE data: %v", err)
	}

	// Create our final CVEs structure
	cves := CVEs{
		LastUpdated:     time.Now(),
		Vulnerabilities: make([]CVE, 0),
	}

	// Process each vulnerability
	for _, item := range rawData["fkie_nvd"] {
		var cveData map[string]interface{}
		err = json.Unmarshal(item[1], &cveData)
		if err != nil {
			continue
		}

		// Extract English description
		var description string
		if descriptions, ok := cveData["descriptions"].([]interface{}); ok {
			for _, desc := range descriptions {
				if d, ok := desc.(map[string]interface{}); ok {
					if lang, ok := d["lang"].(string); ok && lang == "en" {
						if val, ok := d["value"].(string); ok {
							description = val
							break
						}
					}
				}
			}
		}

		// Extract CVSS metrics
		var cvssData map[string]interface{}
		if metrics, ok := cveData["metrics"].(map[string]interface{}); ok {
			if metricV31, ok := metrics["cvssMetricV31"].([]interface{}); ok && len(metricV31) > 0 {
				if metric, ok := metricV31[0].(map[string]interface{}); ok {
					if data, ok := metric["cvssData"].(map[string]interface{}); ok {
						cvssData = data
					}
				}
			}
		}

		// Create CVE entry
		cve := CVE{
			ID:           cveData["id"].(string),
			SourceID:     cveData["sourceIdentifier"].(string),
			Published:    parseTime(cveData["published"].(string)),
			LastModified: parseTime(cveData["lastModified"].(string)),
			VulnStatus:   cveData["vulnStatus"].(string),
			Description:  description,
		}

		// Add CVSS data if available
		if cvssData != nil {
			cve.BaseScore = cvssData["baseScore"].(float64)
			cve.BaseSeverity = cvssData["baseSeverity"].(string)
			cve.VectorString = cvssData["vectorString"].(string)
			cve.Version = cvssData["version"].(string)
			cve.AttackVector = cvssData["attackVector"].(string)
			cve.AttackComplex = cvssData["attackComplexity"].(string)
			cve.PrivRequired = cvssData["privilegesRequired"].(string)
			cve.UserInteraction = cvssData["userInteraction"].(string)
			cve.Scope = cvssData["scope"].(string)
			cve.ConfImpact = cvssData["confidentialityImpact"].(string)
			cve.IntegImpact = cvssData["integrityImpact"].(string)
			cve.AvailImpact = cvssData["availabilityImpact"].(string)
		}

		cves.Vulnerabilities = append(cves.Vulnerabilities, cve)
	}

	// Save to cache
	updatedJSON, err := json.Marshal(cves)
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

	return &cves, nil
}

func parseTime(timeStr string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, timeStr)
	return t
}
