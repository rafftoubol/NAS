> [!NOTE]
> _Main will only get major releases (POC, MVP & Final)._

# Next Attack Surface

NAS _(Next.js Attack Surface)_ is a _Command Line Interface_  to visualize the attack surface of a given Next.js project.


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

## To Do

As a group, we have decided to use **Trello** to organize our tasks and track progress efficiently.
We also define at least two short meeting per week to review the current status of the Project.
> Link to our [**Trello**](https://trello.com/invite/b/67ed2da5c478e38b9a5430cc/ATTI9dad446f498775d2001594cd64afe38d696132E6/attack-surface)

### Our Project Schedule

| Week | Tasks                                                                                       |
|------|---------------------------------------------------------------------------------------------|
| 4    | Research associated technologies,<br/> Develop CLI Interface, Next.js Parser, Config Parser |
| 5    | Research associated technologies, <br />Develop of API Routes Scanner, Dependencies Scanner |
| 6    | Develop of a small but functional **POC** for the visualization process.                    |
| 7*   | Code Refining and Improving in functionalities                                              |
| 8*   | **POC** Deployment for Peer Review                                                              |



## Authors

Group members:

-   Giovanni Menon (_**Menny** in some commit_)
-   Raphael Toubol
-   Nyandoro Christopher
      
