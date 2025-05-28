package codeScanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// Vulnerability represents a detected security issue in code
type Vulnerability struct {
	Path    string // File path where vulnerability was found
	Type    string // Type of vulnerability (e.g., "XSS", "RCE")
	Line    int    // Line number in the file
	Content string // The actual line content containing the vulnerability
}

// CodeScanReport contains all detected vulnerabilities categorized by type
type CodeScanReport struct {
	Methods             []Vulnerability `display:"HTTP Methods"`                 // HTTP method detections
	CORS                []Vulnerability `display:"CORS Vulnerabilities"`         // Open CORS vulnerabilities
	CorsCredentials     []Vulnerability `display:"CORS with Credentials"`        // CORS with credentials enabled
	RCE                 []Vulnerability `display:"Remote Code Execution"`        // Remote Code Execution vulnerabilities
	ApiKey              []Vulnerability `display:"Hardcoded API Keys"`           // Hardcoded API keys
	CommentsSecrets     []Vulnerability `display:"Secrets in Comments"`          // Secrets exposed in comments
	FunctionConstructor []Vulnerability `display:"Function Constructor Usage"`   // Function constructor usage (RCE risk)
	VmModule            []Vulnerability `display:"VM Module Usage"`              // VM module usage (RCE risk)
	HardcodedSecrets    []Vulnerability `display:"Hardcoded Secrets"`            // Hardcoded secrets and passwords
	AWSKeys             []Vulnerability `display:"AWS Access Keys"`              // AWS access key exposures
	JWTSecrets          []Vulnerability `display:"JWT Secret Exposures"`         // JWT secret exposures
	DBUrl               []Vulnerability `display:"Database URL Exposures"`       // Database URL exposures
	ChildProcess        []Vulnerability `display:"Child Process Execution"`      // Child process execution (RCE risk)
	DSetHTML            []Vulnerability `display:"Dangerous HTML Injection"`     // React dangerouslySetInnerHTML usage
	ReactRefsBypass     []Vulnerability `display:"React Refs Bypass"`            // React refs bypassing sanitization
	NextJSScriptBypass  []Vulnerability `display:"Next.js Script Bypass"`        // Next.js Script component bypasses
	NextJSHeadBypass    []Vulnerability `display:"Next.js Head Bypass"`          // Next.js Head component bypasses
	DynamicImports      []Vulnerability `display:"Unsafe Dynamic Imports"`       // Unsafe dynamic imports
	EventHandlers       []Vulnerability `display:"Inline Event Handlers"`        // Inline event handlers (XSS risk)
	JavaScriptURLs      []Vulnerability `display:"JavaScript URLs"`              // JavaScript: URLs in href/src
	ServerSideBypass    []Vulnerability `display:"Server-Side Rendering Bypass"` // Server-side rendering bypasses
	NextJSMiddleware    []Vulnerability `display:"Next.js Middleware Issues"`    // Next.js middleware vulnerabilities
}

// ScanFile reads a single file and detects HTTP methods & security vulnerabilities
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

	// Initialize vulnerability slices
	var methods []Vulnerability
	var cors []Vulnerability
	var rce []Vulnerability
	var apiKey []Vulnerability
	var comments []Vulnerability
	var corsCredentials []Vulnerability
	var hardcodedSecrets []Vulnerability
	var awsKeys []Vulnerability
	var jwtSecrets []Vulnerability
	var dbUrl []Vulnerability
	var childProcess []Vulnerability
	var functionConstructor []Vulnerability
	var vmModule []Vulnerability
	var dsetHTML []Vulnerability
	var reactRefsBypass []Vulnerability
	var nextJSScriptBypass []Vulnerability
	var nextJSHeadBypass []Vulnerability
	var dynamicImports []Vulnerability
	var eventHandlers []Vulnerability
	var javascriptURLs []Vulnerability
	var serverSideBypass []Vulnerability
	var nextJSMiddleware []Vulnerability

	// Original regex patterns for existing vulnerabilities
	reMethods := regexp.MustCompile(`(?i)\b(req|request)\.method\s*(==|===)\s*['"]?(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"]?`)
	reOpenCORS := regexp.MustCompile(`(?i)Access-Control-Allow-Origin.*\*`)
	reEval := regexp.MustCompile(`(?i)\beval\s*\(`)
	reAPIKey := regexp.MustCompile(`(?i)\b(?:const|let|var)\s+\w*(key|token|secret|password)\w*\s*=\s*['"][^'"]+['"]`)
	reCommentSecret := regexp.MustCompile(`(?i)(//|#)\s*\w*(key|token|secret|password)\w*\s*[:=]\s*['"][^'"]+['"]`)
	reCorsCredentials := regexp.MustCompile(`(?i)Access-Control-Allow-Credentials.*true`)
	reFunctionConstructor := regexp.MustCompile(`(?i)new\s+Function\s*\(`)
	reVmModule := regexp.MustCompile(`(?i)(?:vm\.runInThisContext|vm\.runInNewContext)`)
	reHardcodedSecrets := regexp.MustCompile(`(?i)(?:const|let|var)\s+\w*(?:key|token|secret|password|api_key|apikey)\w*\s*=\s*['"][^'"]{8,}['"]`)
	reAWSKey := regexp.MustCompile(`(?i)(?:AKIA[0-9A-Z]{16}|aws_access_key_id|aws_secret_access_key)`)
	reJwtSecret := regexp.MustCompile(`(?i)(?:jwt_secret|jwtSecret)\s*=\s*['"][^'"]+['"]`)
	reDbUrl := regexp.MustCompile(`(?i)(?:database_url|mongodb|postgres|mysql)://[^'"]+`)
	reChildProcess := regexp.MustCompile(`(?i)(?:exec|spawn|execSync|spawnSync)\s*\(`)
	reDsetHtml := regexp.MustCompile(`(?i)dangerouslysetinnerhtml\s*=\s*\{\{\s*__html\s*:\s*.*?}}`)

	// New regex patterns for React/Next.js security bypasses

	// React refs bypassing sanitization (innerHTML, outerHTML, insertAdjacentHTML via refs)
	reReactRefsBypass := regexp.MustCompile(`(?i)\.current\.(innerHTML|outerHTML|insertAdjacentHTML|appendChild|replaceChild|insertBefore|on[a-z]+|setAttribute)\s*[=\(]`)

	// Next.js Script component bypasses
	reNextJSScriptBypass := regexp.MustCompile(`(?i)<Script[^>]*>([\s\S]*?)</Script>|<Script[^>]*dangerouslysetinnerhtml\s*=\s*\{\{[^}]*\}\}`)

	// Next.js Head component with unsafe content
	reNextJSHeadBypass := regexp.MustCompile(`(?i)<Head>[\s\S]*?<script[^>]*>[\s\S]*?</script>[\s\S]*?</Head>|<Head>[\s\S]*?dangerouslysetinnerhtml[\s\S]*?</Head>`)

	// Unsafe dynamic imports with user input
	reDynamicImports := regexp.MustCompile(`(?i)import\s*\(\s*['` + "`" + `"]?\\\$\{.*?\}['` + "`" + `"]?\s*\)|import\s*\(\s*` + "`" + `[^` + "`" + `]*\\\$\{[^}]*\}[^` + "`" + `]*` + "`" + `\s*\)`)

	// Inline event handlers (XSS risk)
	reEventHandlers := regexp.MustCompile(`(?i)(onclick|onload|onerror|onmouseover|onfocus|onblur|onchange|onsubmit|on[a-z]+)\s*=\s*\{.*?\}`)

	// JavaScript: URLs in href/src attributes
	reJavaScriptURLs := regexp.MustCompile(`(?i)(href|src)\s*=\s*\{?\s*['` + "`" + `"]?\s*javascript:`)

	// Server-side rendering bypasses (getServerSideProps, getStaticProps with unsafe content)
	reServerSideBypass := regexp.MustCompile(`(?i)(getServerSideProps|getStaticProps)[\s\S]*?dangerouslysetinnerhtml`)

	// Next.js middleware vulnerabilities
	reNextJSMiddleware := regexp.MustCompile(`(?i)(NextResponse\.redirect\s*\(\s*['` + "`" + `"]?\\\$\{|request\.headers\.set\s*\(\s*['` + "`" + `"][^'` + "`" + `"]*['` + "`" + `"]\s*,\s*.*?\\\$\{)`)

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

		// Detect original vulnerabilities
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
			comments = append(comments, Vulnerability{
				Type:    "CommentSecret",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}

		if reCorsCredentials.MatchString(line) {
			corsCredentials = append(corsCredentials, Vulnerability{
				Type:    "CorsCredentials",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}

		if reFunctionConstructor.MatchString(line) {
			functionConstructor = append(functionConstructor, Vulnerability{
				Type:    "FunctionConstructor",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}

		if reVmModule.MatchString(line) {
			vmModule = append(vmModule, Vulnerability{
				Type:    "VmModule",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}

		if reHardcodedSecrets.MatchString(line) {
			hardcodedSecrets = append(hardcodedSecrets, Vulnerability{
				Type:    "HardcodedSecrets",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}

		if reAWSKey.MatchString(line) {
			awsKeys = append(awsKeys, Vulnerability{
				Type:    "AWSKey",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}

		if reJwtSecret.MatchString(line) {
			jwtSecrets = append(jwtSecrets, Vulnerability{
				Type:    "JwtSecret",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}

		if reDbUrl.MatchString(line) {
			dbUrl = append(dbUrl, Vulnerability{
				Type:    "DbUrl",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}

		if reChildProcess.MatchString(line) {
			childProcess = append(childProcess, Vulnerability{
				Type:    "ChildProcess",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}

		if reDsetHtml.MatchString(line) {
			dsetHTML = append(dsetHTML, Vulnerability{
				Type:    "DangerouslySetHTML",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}

		// Detect new React/Next.js security bypasses

		// React refs bypassing sanitization
		if reReactRefsBypass.MatchString(line) {
			reactRefsBypass = append(reactRefsBypass, Vulnerability{
				Type:    "ReactRefsBypass",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}

		// Next.js Script component bypasses
		if reNextJSScriptBypass.MatchString(line) {
			nextJSScriptBypass = append(nextJSScriptBypass, Vulnerability{
				Type:    "NextJSScriptBypass",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}

		// Next.js Head component bypasses
		if reNextJSHeadBypass.MatchString(line) {
			nextJSHeadBypass = append(nextJSHeadBypass, Vulnerability{
				Type:    "NextJSHeadBypass",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}

		// Unsafe dynamic imports
		if reDynamicImports.MatchString(line) {
			dynamicImports = append(dynamicImports, Vulnerability{
				Type:    "UnsafeDynamicImport",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}

		// Inline event handlers
		if reEventHandlers.MatchString(line) {
			eventHandlers = append(eventHandlers, Vulnerability{
				Type:    "InlineEventHandler",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}

		// JavaScript URLs
		if reJavaScriptURLs.MatchString(line) {
			javascriptURLs = append(javascriptURLs, Vulnerability{
				Type:    "JavaScriptURL",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}

		// Server-side rendering bypasses
		if reServerSideBypass.MatchString(line) {
			serverSideBypass = append(serverSideBypass, Vulnerability{
				Type:    "ServerSideBypass",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}

		// Next.js middleware vulnerabilities
		if reNextJSMiddleware.MatchString(line) {
			nextJSMiddleware = append(nextJSMiddleware, Vulnerability{
				Type:    "NextJSMiddleware",
				Content: line,
				Path:    path,
				Line:    lineNum,
			})
		}
	}

	// Return comprehensive scan results
	return &CodeScanReport{
		Methods:             methods,
		CORS:                cors,
		RCE:                 rce,
		ApiKey:              apiKey,
		CommentsSecrets:     comments,
		CorsCredentials:     corsCredentials,
		FunctionConstructor: functionConstructor,
		VmModule:            vmModule,
		HardcodedSecrets:    hardcodedSecrets,
		AWSKeys:             awsKeys,
		JWTSecrets:          jwtSecrets,
		DBUrl:               dbUrl,
		ChildProcess:        childProcess,
		DSetHTML:            dsetHTML,
		ReactRefsBypass:     reactRefsBypass,
		NextJSScriptBypass:  nextJSScriptBypass,
		NextJSHeadBypass:    nextJSHeadBypass,
		DynamicImports:      dynamicImports,
		EventHandlers:       eventHandlers,
		JavaScriptURLs:      javascriptURLs,
		ServerSideBypass:    serverSideBypass,
		NextJSMiddleware:    nextJSMiddleware,
	}, err
}

// CodeScanner recursively scans all files in a directory tree for security vulnerabilities
func CodeScanner(root string) (*CodeScanReport, error) {
	var allResults CodeScanReport

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories, only scan files
		if info.IsDir() {
			return nil
		}

		// Scan each file starting from the root
		result, err := ScanFile(path)
		if err != nil {
			return err
		}

		// Aggregate all results from individual file scans
		if result != nil {
			allResults.Methods = append(allResults.Methods, result.Methods...)
			allResults.RCE = append(allResults.RCE, result.RCE...)
			allResults.CORS = append(allResults.CORS, result.CORS...)
			allResults.ApiKey = append(allResults.ApiKey, result.ApiKey...)
			allResults.CommentsSecrets = append(allResults.CommentsSecrets, result.CommentsSecrets...)
			allResults.CorsCredentials = append(allResults.CorsCredentials, result.CorsCredentials...)
			allResults.FunctionConstructor = append(allResults.FunctionConstructor, result.FunctionConstructor...)
			allResults.VmModule = append(allResults.VmModule, result.VmModule...)
			allResults.HardcodedSecrets = append(allResults.HardcodedSecrets, result.HardcodedSecrets...)
			allResults.AWSKeys = append(allResults.AWSKeys, result.AWSKeys...)
			allResults.JWTSecrets = append(allResults.JWTSecrets, result.JWTSecrets...)
			allResults.DBUrl = append(allResults.DBUrl, result.DBUrl...)
			allResults.ChildProcess = append(allResults.ChildProcess, result.ChildProcess...)
			allResults.DSetHTML = append(allResults.DSetHTML, result.DSetHTML...)
			allResults.ReactRefsBypass = append(allResults.ReactRefsBypass, result.ReactRefsBypass...)
			allResults.NextJSScriptBypass = append(allResults.NextJSScriptBypass, result.NextJSScriptBypass...)
			allResults.NextJSHeadBypass = append(allResults.NextJSHeadBypass, result.NextJSHeadBypass...)
			allResults.DynamicImports = append(allResults.DynamicImports, result.DynamicImports...)
			allResults.EventHandlers = append(allResults.EventHandlers, result.EventHandlers...)
			allResults.JavaScriptURLs = append(allResults.JavaScriptURLs, result.JavaScriptURLs...)
			allResults.ServerSideBypass = append(allResults.ServerSideBypass, result.ServerSideBypass...)
			allResults.NextJSMiddleware = append(allResults.NextJSMiddleware, result.NextJSMiddleware...)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return &allResults, nil
}
