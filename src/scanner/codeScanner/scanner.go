package codeScanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

type Vulnerability struct {
	Path    string
	Type    string
	Line    int
	Content string
}

type CodeScanReport struct {
	Methods         []Vulnerability
	CORS            []Vulnerability
	RCE             []Vulnerability
	ApiKey          []Vulnerability
	CoomentsSecrets []Vulnerability
}

// Scan reads the file and detects HTTP methods & vulnerabilities
func ScanFile(path string) (*CodeScanReport, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		if err := file.Close(); err != nil {
			fmt.Printf("Error closing file: %v", err)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	methodMap := map[string]bool{}

	var methods []Vulnerability
	var cors []Vulnerability
	var rce []Vulnerability
	var apiKey []Vulnerability
	var comments []Vulnerability

	// Regex for detection
	reMethods := regexp.MustCompile(`(?i)\b(req|request)\.method\s*(==|===)\s*['"]?(GET|POST|PUT|DELETE|PATCH)['"]?`)
	reOpenCORS := regexp.MustCompile(`(?i)Access-Control-Allow-Origin.*\*`)
	reEval := regexp.MustCompile(`(?i)\beval\s*\(`)
	reAPIKey := regexp.MustCompile(`(?i)\b(?:const|let|var)\s+\w*(key|token|secret|password)\w*\s*=\s*['"][^'"]+['"]`)
	reCommentSecret := regexp.MustCompile(`(?i)(//|#)\s*\w*(key|token|secret|password)\w*\s*[:=]\s*['"][^'"]+['"]`)

	lineNum := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		// Detect HTTP Methods
		if match := reMethods.FindStringSubmatch(line); match != nil {
			method := match[2]
			if !methodMap[method] {
				methods = append(methods, Vulnerability{
					Type:    method,
					Content: line,
					Path:    path,
					Line:    lineNum,
				})
				methodMap[method] = true
			}
		}

		// Detect vulnerabilities
		if reOpenCORS.MatchString(line) {
			cors = append(cors, Vulnerability{
				Type:    "OpenCORS",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}

		if reEval.MatchString(line) {
			rce = append(rce, Vulnerability{
				Type:    "Eval",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}

		if reAPIKey.MatchString(line) {
			apiKey = append(apiKey, Vulnerability{
				Type:    "APIKey",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}

		if reCommentSecret.MatchString(line) {
			apiKey = append(comments, Vulnerability{
				Type:    "CommentSecret",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}
	}

	return &CodeScanReport{
		Methods:         methods,
		CORS:            cors,
		RCE:             rce,
		ApiKey:          apiKey,
		CoomentsSecrets: comments,
	}, err
}

func CodeScanner(root string) (*CodeScanReport, error) {
	var allResults CodeScanReport

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Scan each file starting from the root
		result, err := ScanFile(path)

		if err != nil {
			return err
		}

		// For each result found save it
		if result != nil {
			allResults.Methods = append(allResults.Methods, result.Methods...)
			allResults.RCE = append(allResults.RCE, result.RCE...)
			allResults.CORS = append(allResults.CORS, result.CORS...)
			allResults.ApiKey = append(allResults.ApiKey, result.ApiKey...)
			allResults.CoomentsSecrets = append(allResults.CoomentsSecrets, result.CoomentsSecrets...)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return &allResults, nil
}
