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
	Short: "Discovers dangerous code pattern in the Next.js project",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		// Create a config from the argument
		cfg := config.NewConfig().
			WithProjectPath(args[0]).
			WithCodeScan(true).
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
		scanner, err := scanner.NewScanner(cfg)
		if err != nil {
			logrus.Fatalln(err)
		}
		// Execute Scanner
		if err := scanner.Scan(); err != nil {
			logrus.Fatalln(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(codeCmd)
}
