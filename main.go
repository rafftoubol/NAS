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

	config_path := flag.String("c", "", "configuration file path")
	flag.Parse()

	if *config_path != "" {
		cfg, err := config.LoadConfig(*config_path)

		if err != nil {
			log.Fatalf("Error: %s", err)
		}

		log.Printf(": %+v\n", *cfg)

		if err := cfg.LoadConfigRepo(); err != nil {
			log.Fatalf("Error: %s", err)
		}
	}

}
