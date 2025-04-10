package cli

import (
	api "attack-surface/src/api"
	config "attack-surface/src/utils"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
)

var outputPath string

var apiCmd = &cobra.Command{
	Use:   "api [project_path]",
	Short: "Discovers API routes in the Next.js project",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			logrus.Fatalln("Missing project path argument. Please provide the project path as an argument.")

		}

		config, _ := config.NewConfigBuilder().
			DefProjectPath(args[0]).
			DefApiScan(true).
			WithDefaults().
			Build()

		if err := config.Validate(); err != nil {
			logrus.Fatalln(err)
		}

		if err := config.LoadConfigRepo(); err != nil {
			logrus.Fatalln(err)
		}
		fmt.Println(config.ProjectPath, config.OutputPath, config.ApiScan, config.DependenciesScan)
		api.DiscoverAPIRoutes(config.ProjectPath)
	},
}

func init() {
	apiCmd.Flags().StringVarP(&outputPath, "output", "o", ".", "Output path for the results")
	rootCmd.AddCommand(apiCmd)
}
