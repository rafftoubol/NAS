package main

import (
	config "attack-surface/src/utils"
	"flag"
	"fmt"
	"log"
)

func main() {
	fmt.Println(` ________   ________  ________      
|\   ___  \|\   __  \|\   ____\     
\ \  \\ \  \ \  \|\  \ \  \___|_    
 \ \  \\ \  \ \   __  \ \_____  \   
  \ \  \\ \  \ \  \ \  \|____|\  \  
   \ \__\\ \__\ \__\ \__\____\_\  \ 
    \|__| \|__|\|__|\|__|\_________\
                        \|_________|`)

	configPath := flag.String("c", "", "configuration file path")
	flag.Parse()

	if *configPath != "" {
		cfg, err := config.LoadConfig(*configPath)

		if err != nil {
			log.Fatalf("Error: %s", err)
		}

		log.Printf(": %+v\n", *cfg)

		if err := cfg.LoadConfigRepo(); err != nil {
			log.Fatalf("Error: %s", err)
		}

		log.Printf(": %+v\n", *cfg)
	}

}
