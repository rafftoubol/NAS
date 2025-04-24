package cli

import (
	"attack-surface/src/scanner"
	"attack-surface/src/utils"
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

		if err := utils.LoadConfig(args[0]); err != nil {
			logrus.Fatalln(err)
		}

		if err := utils.NasConfig.LoadConfigRepo(); err != nil {
			logrus.Fatalln(err)
		}

		next, err := utils.InitNext(utils.NasConfig.ProjectPath)
		if err != nil {
			logrus.Fatalln(err)
		}

		if err := scanner.Scanner(next.Dependencies); err != nil {
			logrus.Fatalln(err)
		}

		if err := scanner.Scanner(next.DevDependencies); err != nil {
			logrus.Fatalln(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
