package route_analysis

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
)

// AnalyzeAPIFile analyzeAPIFile reads the file and detects HTTP methods & vulnerabilities
func AnalyzeAPIFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		fmt.Println("❌ Error reading file:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	methods := map[string]bool{}
	vulnerabilities := []string{}

	// Regular expressions for detection
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

	// Print results
	fmt.Println("   Methods:", keys(methods))
	if len(vulnerabilities) > 0 {
		fmt.Println("   ❗ Vulnerabilities found:")
		for _, v := range vulnerabilities {
			fmt.Println("     -", v)
		}
	} else {
		fmt.Println("   ✅ No vulnerabilities detected")
	}
}

// keys extracts keys from a map
func keys(m map[string]bool) []string {
	result := []string{}
	for k := range m {
		result = append(result, k)
	}
	return result
}
