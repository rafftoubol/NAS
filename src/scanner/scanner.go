/*
The purpose of this file is to reshape next.dependencies, and next.devDependencies into a OSV-Scanner payload so that
we can simply curl a batch of packages and versions, receive the response as json

PRE: Defined and filled Next struct (next)
POST: Struct with vulnerabilities



*/

package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"strings"
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

/*
Scanner this function forms the dependencies and makes the request to the OSV API,
when we have more scan function we can rename this to dependency scanner, and wrap it in another func - scanner again
*/
func Scanner(dependenciesMap map[string]string) error {
	//dependenciesMap := utils.GlobalNext.Dependencies
	queries := DependencyMapper(dependenciesMap)

	// Pretty print the request payload

	if err := prettyPrintRequest(queries); err != nil {
		return err
	}

	resBody, err := OSVRequestHandler(queries)
	if err != nil {
		return err
	}

	logrus.Infoln(string(resBody))

	// Format and print JSON response
	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, resBody, "", "  ")
	if err != nil {
		return fmt.Errorf("Error formatting JSON: %w ", err)
	}
	return nil
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
OSVRequestHandler this functions purpose is to make batch requests to the OSV API, determining vulnerabilities,
returning JSON of CVSS

PRE: already shaped OSVQueries from the dependency Mapper
POST: Either the JSON Response as bytes or an error
*/
func OSVRequestHandler(queries []OSVQuery) ([]byte, error) {
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
