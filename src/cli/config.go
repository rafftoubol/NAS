package cli

import (
	"attack-surface/src/utils"
	"github.com/spf13/cobra"
	"log"
)

var configCmd = &cobra.Command{
	Use:   "config [config_file_path]",
	Short: "Load configuration from	 a JSON, TOML, YAML, HCL file",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatalf("Please provide the config file path")
		}

		if err := utils.LoadConfig(args[0]); err != nil {
			log.Fatalf("Error loading config: %v", err)
		}

		if err := utils.NasConfig.LoadConfigRepo(); err != nil {
			log.Fatalf("Error loading repo %v:", err)
		}

		if _, err := utils.InitNext(utils.NasConfig.ProjectPath); err != nil {
			log.Fatalf("Error: %s", err)
		}

	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
