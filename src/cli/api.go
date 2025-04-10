package cli

import (
	api "attack-surface/src/api"
	config "attack-surface/src/utils"
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

var outputPath string

var apiCmd = &cobra.Command{
	Use:   "api [project_path]",
	Short: "Discovers API routes in the Next.js project",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println("Missing project path argument. Please provide the project path as an argument.")
			os.Exit(1)
		}

		config, _ := config.NewConfigBuilder().
			DefProjectPath(args[0]).
			DefApiScan(true).
			WithDefaults().
			Build()

		if err := config.Validate(); err != nil {
			fmt.Println("🛑", err.Error())
			os.Exit(1)
		}

		if err := config.LoadConfigRepo(); err != nil {
			fmt.Println("🛑", err.Error())
			os.Exit(1)
		}
		fmt.Println(config.ProjectPath, config.OutputPath, config.ApiScan, config.DependenciesScan)
		api.DiscoverAPIRoutes(config.ProjectPath)
	},
}

func init() {
	apiCmd.Flags().StringVarP(&outputPath, "output", "o", ".", "Output path for the results")
	rootCmd.AddCommand(apiCmd)
}
