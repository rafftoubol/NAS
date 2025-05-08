/*
The point of this file is to add the functionality to specify the API Scan functionality via the cli, instead of just
from the config file -- this is secondary functionality really

PRE: CLI Inputs (ARGS), projectpath
POST: config with defaults

...???
*/

package cli

import (
	config "attack-surface/src/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var outputPath string

var apiCmd = &cobra.Command{
	Use:   "apiScanner [project_path]",
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
		/* Debug Printing Leaving it here in case I need it again
		fmt.Println("Project Path:", config.ProjectPath, "Output Path:", config.OutputPath, "API Scan T/F", config.ApiScan, "Dependency Scan T/F", config.DependenciesScan)
		*/
		// apiScanner.DiscoverAPIRoutes(config.ProjectPath)
	},
}

func init() {
	apiCmd.Flags().StringVarP(&outputPath, "output", "o", ".", "Output path for the results")
	rootCmd.AddCommand(apiCmd)
}
