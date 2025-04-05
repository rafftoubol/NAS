package cli

import (
	routeAnalysis "attack-surface/src/route-analysis"
	config "attack-surface/src/utils"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
)

var outputPath string

var apiCmd = &cobra.Command{
	Use:   "api [project_path]",
	Short: "Discovers API routes in the Next.js project",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println("Missing project path argument. Please provide the project path as an argument.")
			os.Exit(1)
		}

		config := config.Config{
			ProjectPath: args[0],
			OutputPath:  outputPath,
		}

		if err := config.Validate(); err != nil {
			fmt.Println("🛑", err.Error())
			os.Exit(1)
		}

		if err := config.LoadConfigRepo(); err != nil {
			fmt.Println("🛑", err.Error())
			os.Exit(1)
		}

		discoverAPIRoutes(config.ProjectPath)

	},
}

func discoverAPIRoutes(root string) {
	fmt.Println("🔍 Scanning for API routes in:", root)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// TODO: Unhandled Error
		routeAnalysis.AnalyzeAPIFile(path)
		return nil
	})

	if err != nil {
		fmt.Println("❌ Error scanning:", err)
	}
}

func init() {
	apiCmd.Flags().StringVarP(&outputPath, "output", "o", ".", "Output path for the results")
	rootCmd.AddCommand(apiCmd)
}
