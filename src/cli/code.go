/*
The point of this file is to add the functionality to specify the API Scan functionality via the cli, instead of just
from the config file -- this is secondary functionality really

PRE: CLI Inputs (ARGS), projectpath
POST: config with defaults

...???
*/

package cli

import (
	"attack-surface/src/scanner"
	"attack-surface/src/utils/config"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var codeCmd = &cobra.Command{
	Use:   "code [project_path]",
	Short: "Discovers API routes in the Next.js project",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			logrus.Fatalln("Missing project path argument. Please provide the project path as an argument.")

		}
		// Create a config from the argument
		cfg, _ := config.NewConfigBuilder().
			DefProjectPath(args[0]).
			DefCodeScan(true).
			WithDefaults().
			Build()
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
	rootCmd.AddCommand(codeCmd)
}
