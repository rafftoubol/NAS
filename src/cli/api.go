package cli

import (
	routeAnalysis "attack-surface/src/route-analysis"
	config "attack-surface/src/utils"
	"fmt"
	"github.com/spf13/cobra"
	"log"
	"os"
	"path/filepath"
)

var outputPath string

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Discovers API routes in the Next.js project",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatalf("Please provide the project file location")
		}

		config := config.Config{
			ProjectPath: args[0],
			OutputPath:  outputPath,
		}

		if err := config.Validate(); err != nil {
			log.Fatalf(err.Error())
		}

		if err := config.LoadConfigRepo(); err != nil {
			log.Fatalf(err.Error())
		}

		fmt.Println("📁 ProjectPath:", config.ProjectPath)
		fmt.Println("📦 OutputPath:", config.OutputPath)

		discoverAPIRoutes(config.ProjectPath)

	},
}

func discoverAPIRoutes(root string) {
	fmt.Println("🔍 Scanning for API routes in:", root)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

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
