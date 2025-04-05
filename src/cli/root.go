package cli

import (
	"fmt"
	"github.com/spf13/cobra"
	"log"
)

var rootCmd = &cobra.Command{
	Use:   "cli",
	Short: "",
	Long:  "",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf(err.Error())
	}
}

func init() {
	cobra.OnInitialize(initProject)
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}

func initProject() {
	fmt.Println("\033[31m" + ` ________   ________  ________      
|\   ___  \|\   __  \|\   ____\     
\ \  \\ \  \ \  \|\  \ \  \___|_    
 \ \  \\ \  \ \   __  \ \_____  \   
  \ \  \\ \  \ \  \ \  \|____|\  \  
   \ \__\\ \__\ \__\ \__\____\_\  \ 
    \|__| \|__|\|__|\|__|\_________\
                        \|_________|` + "\033[0m")

	// TODO : Insert here logic for refresh cache
}
