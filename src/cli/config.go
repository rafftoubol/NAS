package cli

import (
	"attack-surface/src/utils"
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

var configCmd = &cobra.Command{
	Use:   "config [config_file_path]",
	Short: "Load configuration from	a JSON, TOML, YAML, HCL file",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println("Missing config file path argument. Please provide the config file path as an argument.")
			os.Exit(1)
		}

		if err := utils.LoadConfig(args[0]); err != nil {
			fmt.Println("🛑", err.Error())
			os.Exit(1)
		}

		if err := utils.NasConfig.LoadConfigRepo(); err != nil {
			fmt.Println("🛑", err.Error())
			os.Exit(1)
		}

		if _, err := utils.InitNext(utils.NasConfig.ProjectPath); err != nil {
			fmt.Println("🛑", err.Error())
			os.Exit(1)
		}

	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
