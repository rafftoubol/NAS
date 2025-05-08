package cli

import (
	"attack-surface/src/utils/config"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config [config_file_path]",
	Short: "Load configuration from	a JSON, TOML, YAML, HCL file",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			logrus.Fatalln("Missing config file path argument. Please provide the config file path as an argument.")

		}
		// Create a config from the config file
		cfg, err := config.LoadConfigFile(args[0])
		if err != nil {
			logrus.Fatalln(err)
		}

		// Clone the repository
		if err := cfg.LoadConfigRepo(); err != nil {
			logrus.Fatalln(err)
		}

	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
