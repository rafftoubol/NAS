/*
The purpose of this file is to reshape next.dependencies, and next.devDependencies into a OSV-DepScanner payload so that
we can simply curl a batch of packages and versions, receive the response as json

PRE: Defined and filled Next struct (next)
POST: Struct with vulnerabilities



*/

package depScanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"strings"
	"time"
)

// OSVQuery Struct for specifying a package in the API
type OSVQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

// OSVBatchRequest Struct for bundling many OSVQueries
type OSVBatchRequest struct {
	Queries []OSVQuery `json:"queries"`
}

type Vuln struct {
	ID       string          `json:"id"`
	Modified string          `json:"modified"`
	Details  json.RawMessage `json:"details,omitempty"`
}

type Result struct {
	Vulns []Vuln `json:"vulns,omitempty"`
}

type Response struct {
	Results []Result `json:"results"`
}

/*
DepScanner this function forms the dependencies and makes the request to the OSV API,
when we have more scan function we can rename this to dependency scanner, and wrap it in another func - scanner again
*/
func DepScanner(dependenciesMap map[string]string) (*Response, error) {
	//dependenciesMap := utils.GlobalNext.Dependencies
	queries := DependencyMapper(dependenciesMap)

	// Pretty print the request payload

	if err := prettyPrintRequest(queries); err != nil {
		return nil, err
	}

	resBody, err := OSVIDFetcher(queries)
	if err != nil {
		return nil, err
	}

	var depReport Response

	err = json.Unmarshal(resBody, &depReport)
	if err != nil {
		return nil, fmt.Errorf("errore nel parsing JSON: %w", err)
	}

	// Format and print JSON response
	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, resBody, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("Error formatting JSON: %w ", err)
	}

	// Call OSVDetailFetcher to fetch details for the vulnerabilities
	_, err = OSVDetailFetcher(&depReport) // We discard the returned []byte for simplicity as per the request
	if err != nil {
		fmt.Printf("Error fetching vulnerability details: %v\n", err) // Or handle the error as needed
		// Depending on your error handling strategy, you might want to return the error here.
		// For the bare minimum, we'll just print it.
	}

	return &depReport, nil
}

/*
DependencyMapper Function for mapping the data in the next dependencies struct field to an OSVQuery format
With Package -> Name, Version & Ecosystem
*/
func DependencyMapper(dependencies map[string]string) []OSVQuery {
	queries := make([]OSVQuery, 0, len(dependencies))
	// Process each dependency
	for pkg, ver := range dependencies {
		query := OSVQuery{}

		// Remove leading @ if present
		pkgName := pkg
		if strings.HasPrefix(pkg, "@") {
			pkgName = pkg[1:]
		}
		query.Package.Name = pkgName
		query.Package.Ecosystem = "npm" // Assuming all are npm packages, when next.go is modified change this

		// Remove ^ or ~ from version
		version := ver
		if strings.HasPrefix(ver, "^") || strings.HasPrefix(ver, "~") {
			version = ver[1:]
		}
		query.Version = version

		queries = append(queries, query)
	}
	return queries
}

/*
OSVIDFetcher this functions purpose is to make batch requests to the OSV API, determining vulnerabilities,
returning JSON of CVSS

PRE: already shaped OSVQueries from the dependency Mapper
POST: Either the JSON Response as bytes or an error
*/
func OSVIDFetcher(queries []OSVQuery) ([]byte, error) {
	OSVRequest := OSVBatchRequest{
		Queries: queries,
	}
	// Convert request to JSON
	jsonPayload, err := json.Marshal(OSVRequest)
	if err != nil {

		return nil, fmt.Errorf("Error marshaling JSON: %w ", err)
	}

	// Make the HTTP request to OSV API
	resp, err := http.Post(
		"https://api.osv.dev/v1/querybatch",
		"application/json",
		bytes.NewBuffer(jsonPayload),
	)
	if err != nil {
		return nil, fmt.Errorf("Error making request: %w ", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			logrus.Errorln("Error reading response: ", err)
		}
	}(resp.Body)

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading response: %w ", err)
	}

	return body, nil
}

/*
OSVDetailFetcher A function to take the vulnerability ID's and loop through fetching the details
*/
func OSVDetailFetcher(response *Response) ([]byte, error) {
	client := &http.Client{
		Timeout: time.Second * 10,
	}

	var allDetails []json.RawMessage // To store the details fetched for all vuln IDs

	// Iterate through each Result in the response
	for _, result := range response.Results {
		// Iterate through each Vuln in the current Result
		for _, vuln := range result.Vulns {
			// Create URL with the vulnerability ID
			url := fmt.Sprintf("https://api.osv.dev/v1/vulns/%s", vuln.ID)
			fmt.Println("Fetching details for:", vuln.ID) // For debugging

			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return nil, fmt.Errorf("error creating request for %s: %w", vuln.ID, err)
			}

			resp, err := client.Do(req)
			if err != nil {
				return nil, fmt.Errorf("error fetching details for %s: %w", vuln.ID, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("unexpected status code %d for %s", resp.StatusCode, vuln.ID)
			}

			var detailResponse map[string]interface{} // Or a more specific struct if you know the detail structure
			err = json.NewDecoder(resp.Body).Decode(&detailResponse)
			if err != nil {
				return nil, fmt.Errorf("error decoding response for %s: %w", vuln.ID, err)
			}

			// Assuming the API returns a single JSON object with details
			detailBytes, err := json.Marshal(detailResponse)
			if err != nil {
				return nil, fmt.Errorf("error marshaling details for %s: %w", vuln.ID, err)
			}
			allDetails = append(allDetails, detailBytes)
		}
	}

	// You might want to return all the fetched details in a single JSON array
	finalResponse, err := json.Marshal(allDetails)
	if err != nil {
		return nil, fmt.Errorf("error marshaling final response: %w", err)
	}

	fmt.Println("Fetched details for:", string(finalResponse))

	return finalResponse, nil
}

/*
prettyPrintRequest just for testing really
*/
func prettyPrintRequest(queries []OSVQuery) error {
	// Create the OSV API request payload
	request := OSVBatchRequest{
		Queries: queries,
	}

	// Convert request to JSON
	jsonPayload, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("Error marshaling JSON: %w ", err)
	}

	// Format JSON for pretty printing
	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, jsonPayload, "", "  ")
	if err != nil {
		return fmt.Errorf("Error formatting JSON: %w ", err)
	}

	//logrus.Infof("OSV API Request Payload: %v", prettyJSON.String())

	return nil
}
