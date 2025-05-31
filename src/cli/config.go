package cli

import (
	"attack-surface/src/scanner"
	"attack-surface/src/utils/config"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config [config_file_path]",
	Short: "Load configuration from	a JSON, TOML, YAML, HCL file",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		// Create a config from the config file
		cfg, err := config.LoadConfigFile(args[0])
		if err != nil {
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
	rootCmd.AddCommand(configCmd)
}
