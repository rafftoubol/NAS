package cli

import (
	"attack-surface/src/utils"
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

var (
	verbose bool
	rootCmd = &cobra.Command{
		Use:   "nas",
		Short: "",
		Long:  "",
		Run: func(cmd *cobra.Command, args []string) {

		},
	}
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initProject)
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Display additional information")
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
	utils.SetUpLogger(verbose)
}
