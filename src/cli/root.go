package cli

import (
	"attack-surface/src/utils"
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

var (
	OutputPath          string
	verbose             bool
	PerformanceTracking bool
	performanceMonitor  *utils.PerformanceMonitor
	rootCmd             = &cobra.Command{
		Use:   "nas",
		Short: "",
		Long:  "",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {

		},
	}
)

func Execute() {
	err := rootCmd.Execute()

	if PerformanceTracking && performanceMonitor != nil {
		performanceMonitor.Stop()
	}

	if err != nil {

		os.Exit(1)
	}

}

func init() {
	cobra.OnInitialize(initProject)
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Display additional information")
	rootCmd.PersistentFlags().BoolVarP(&PerformanceTracking, "performance", "p", false, "Display additional information about the performance of the scanner")

	rootCmd.PersistentFlags().StringVarP(&OutputPath, "report", "o", "./report.pdf", "Output path for the results")
}

func initProject() {
	if PerformanceTracking {
		performanceMonitor = utils.NewPerformanceMonitor()
	}
	fmt.Println("\033[31m" + ` ________   ________  ________      
|\   ___  \|\   __  \|\   ____\     
\ \  \\ \  \ \  \|\  \ \  \___|_    
 \ \  \\ \  \ \   __  \ \_____  \   
  \ \  \\ \  \ \  \ \  \|____|\  \  
   \ \__\\ \__\ \__\ \__\____\_\  \ 
    \|__| \|__|\|__|\|__|\_________\
                        \|_________|` + "\033[0m")
	utils.SetUpLogger(verbose)
}
