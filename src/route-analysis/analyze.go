package route_analysis

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
)

//TODO: Create a type struct with t

// AnalyzeAPIFile reads the file and detects HTTP methods & vulnerabilities
func AnalyzeAPIFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("❌ Error reading file: %v", err)
	}
	defer func(file *os.File) {
		if err := file.Close(); err != nil {
			fmt.Printf("❌ Error closing file: %v", err)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	methods := map[string]bool{}
	var vulnerabilities []string

	// Regex for detection. Could be modified if a better solution is available
	reMethods := regexp.MustCompile(`(?i)(req\.method\s*===\s*['"]?(GET|POST|PUT|DELETE)['"]?)`)
	reOpenCORS := regexp.MustCompile(`(?i)Access-Control-Allow-Origin.*\*`)
	reEval := regexp.MustCompile(`(?i)\beval\s*\(`)
	reAPIKey := regexp.MustCompile(`(?i)(Authorization\s*:\s*['"]Bearer\s+[A-Za-z0-9-_]+['"])|(process\.env\.[A-Z_]+_KEY)`)

	for scanner.Scan() {
		line := scanner.Text()

		// Detect HTTP Methods
		if match := reMethods.FindStringSubmatch(line); match != nil {
			methods[match[2]] = true
		}

		// Detect vulnerabilities
		if reOpenCORS.MatchString(line) {
			vulnerabilities = append(vulnerabilities, "⚠️ Open CORS policy detected!")
		}
		if reEval.MatchString(line) {
			vulnerabilities = append(vulnerabilities, "🚨 Dangerous 'eval()' usage detected!")
		}
		if reAPIKey.MatchString(line) {
			vulnerabilities = append(vulnerabilities, "🚨 Hardcoded API key or Authorization header detected!")
		}
	}

	// Print results. Improvements needed here for results
	fmt.Println("   Methods:", keys(methods))
	if len(vulnerabilities) > 0 {
		fmt.Println("   ❗ Vulnerabilities found:")
		for _, v := range vulnerabilities {
			fmt.Println("     -", v)
		}
	} else {
		fmt.Println("   ✅ No vulnerabilities detected")
	}
	return nil
}

// keys extracts keys from a map
func keys(m map[string]bool) []string {
	var result []string
	for k := range m {
		result = append(result, k)
	}
	return result
}
