package cli

import (
	"attack-surface/src/scanner"
	"attack-surface/src/utils/config"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var dependenciesCmd = &cobra.Command{
	Use:   "dependencies [project path]",
	Short: "Lists all dependencies of a project",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		projectPath := args[0]

		cfg := config.NewConfig().
			WithProjectPath(projectPath).
			WithDependenciesScan(true).
			WithOutputPath(OutputPath)

		// Validation of the config
		if err := cfg.Validate(); err != nil {
			logrus.Fatalln(err)
		}
		// Clone the repository
		if err := cfg.LoadConfigRepo(); err != nil {
			logrus.Fatalln(err)
		}

		// Scanner Creation
		scanner := scanner.NewScanner(cfg)
		// Execute Scanner
		if err := scanner.Scan(); err != nil {
			logrus.Fatalln(err)
		}

	},
}

func init() {
	rootCmd.AddCommand(dependenciesCmd)
}
