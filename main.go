package main

import (
	utils "attack-surface/src/utils"
	"flag"
	"fmt"
	"log"
)

func main() {
	fmt.Println("\033[31m" + ` ________   ________  ________      
|\   ___  \|\   __  \|\   ____\     
\ \  \\ \  \ \  \|\  \ \  \___|_    
 \ \  \\ \  \ \   __  \ \_____  \   
  \ \  \\ \  \ \  \ \  \|____|\  \  
   \ \__\\ \__\ \__\ \__\____\_\  \ 
    \|__| \|__|\|__|\|__|\_________\
                        \|_________|` + "\033[0m")

	configPath := flag.String("c", "", "configuration file path")
	flag.Parse()

	if *configPath != "" {
		cfg, err := utils.LoadConfig(*configPath)

		if err != nil {
			log.Fatalf("Error: %s", err)
		}

		if err := cfg.LoadConfigRepo(); err != nil {
			log.Fatalf("Error: %s", err)
		}

		next, err := utils.InitNext(cfg.ProjectPath)
		if err != nil {
			log.Fatalf("Error: %s", err)
		}
		fmt.Println("Project Name:", next.Name)
		fmt.Println("Project Version:", next.Version)
		fmt.Println("Next Version:", next.Dependencies["next"])
	}

}
