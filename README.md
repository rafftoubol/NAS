> [!NOTE]
> _Main will only get major releases (POC, MVP & Final)._

# Next Attack Surface

NAS _(Next.js Attack Surface)_ is a _Command Line Interface_  to visualize the attack surface of a given Next.js project.

### Features

| Feature | Status |
| :--- | :---: |
| Full Software Composition Analysis | ✅ |
| Static Analysis for commonly unsafe patterns, lack of sanitization and hardcoded credentials | ✅ |
| NextJS specific unsafe patterns | ✅ |
| Intuitive and clean CLI output | ✅ |
| Vulnerability report PDF with remediation steps, CVE details, and code snippets | ✅ |

## Set Up

```go 
`________   ________  ________      
|\   ___  \|\   __  \|\   ____\     
\ \  \\ \  \ \  \|\  \ \  \___|_    
 \ \  \\ \  \ \   __  \ \_____  \   
  \ \  \\ \  \ \  \ \  \|____|\  \  
   \ \__\\ \__\ \__\ \__\____\_\  \ 
    \|__| \|__|\|__|\|__|\_________\
                        \|_________|`

Usage:
  nas [flags]
  nas [command]

Available Commands:
  code         Discovers dangerous code pattern in the Next.js project
  config       Load configuration from  a JSON, TOML, YAML, HCL file
  dependencies Lists all dependencies of a project
  help         Help about any command
  scan         Code Scan + Dependency Scan

Flags:
  -h, --help            help for nas
  -o, --report string   Output path for the results (default "./report.pdf")
  -v, --verbose         Display additional information
```

### Example of usage

Config file example is already present in `examples/config.yaml` with a _Next.js_ vulnerable project. 
```bash
go run main.go config examples/config.yaml -v
```

### To-Do
Add other framework specific rules.
expand SAST ruleset. 

