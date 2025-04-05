package cli

import (
	"attack-surface/src/utils"
	"fmt"
	"github.com/spf13/cobra"
	"log"
)

var configCmd = &cobra.Command{
	Use:   "config [path_to_config]",
	Short: "Load configuration from a JSON, TOML, YAML, HCL file",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatalf("Please provide the config file path")
		}

		configPath := args[0]
		fmt.Println("Loading config from:", configPath)
		if err := utils.LoadConfig(configPath); err != nil {
			log.Fatalf("Error loading config: %v", err)
		}

		if err := utils.NasConfig.LoadConfigRepo(); err != nil {
			log.Fatalf("Error loading repo %v:", err)
		}

		next, err := utils.InitNext(utils.NasConfig.ProjectPath)
		if err != nil {
			log.Fatalf("Error: %s", err)
		}
		fmt.Println("Project Name:", next.Name)
		fmt.Println("Project Version:", next.Version)
		fmt.Println("Next Version:", next.Dependencies["next"])

	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
