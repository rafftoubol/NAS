package cli

import (
	"attack-surface/src/utils"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
)

var (
	OutputPath string
	verbose    bool

	rootCmd = &cobra.Command{
		Use:   "nas",
		Short: "",
		Long:  "",
		Args:  cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {

				cmd.Help()
				return
			}

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
	rootCmd.PersistentFlags().StringVarP(&OutputPath, "report", "o", "./report.pdf", "Output path for the results")
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
	utils.SetUpLogger(verbose)

	if _, err := utils.CVECacheChecker(); err != nil {
		logrus.Fatalln(err)
	} else {
		logrus.Debugln("CVE cache validated")
	}

}
