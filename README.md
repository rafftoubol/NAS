> _Please see readme in DEVELOP Branch for the most up to date and detailed information (Including readme)._
> 
> _Main will only get major releases (POC, MVP & Final)._

# Next Attack Surface

NAS _(Next.js Attack Surface)_ is a _Command Line Interface_  to visualize the attack surface of a given Next.js project.

## To Do

As a group, we have decided to use **Trello** to organize our tasks and track progress efficiently.
We also define at least two short meeting per week to review the current status of the Project.
> Link to our [**Trello**](https://trello.com/invite/b/67ed2da5c478e38b9a5430cc/ATTI9dad446f498775d2001594cd64afe38d696132E6/attack-surface)  

### Our Project Schedule

| Week | Tasks                                                                                       |
|------|---------------------------------------------------------------------------------------------|
| 1*   | Research associated technologies,<br/> Develop CLI Interface, Next.js Parser, Config Parser |
| 2    | Research associated technologies, <br />Develop of API Routes Scanner, Dependencies Scanner |
| 3    | Develop of a small but functional **POC** for the visualization process.                    |
| 4    | Code Refining and Improving in functionalities                                              |


## Security Aspects

- Obsolete and vulnerable dependencies
- Misconfigured API routes
- Unsecured HTTP headers


## Architecture 

- **Scanner Module** : Responsible for scanning the dependencies and API routes.
- **Visualization Module** : Generate the visualization of the attack surface from the scanning process.
- **Report Generator** : Compile the findings into a structured report _(PDF,HTML)_.
- **CLI Interface:** : Command Line Interface

The visual draft of the architecture can be viewed [here](https://excalidraw.com/#json=eOSnuwrJvgsdgsHzBxNv-,69EJhqRWTUTs13yfYTpSYQ).

### Utilities 

- Configuration options file  
- PDF/HTML(?) output for visual representation

## Authors

Group members:

-   Giovanni Menon (_**Menny** in some commit_)
-   Raphael Toubol
-   Nyandoro Christopher
      
