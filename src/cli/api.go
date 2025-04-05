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

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Discovers API routes in the Next.js project",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatalf("Please provide the path")
		}
		discoverAPIRoutes(args[0])

		if !config.IsLoaded() {
			log.Fatalf("Please provide the path2")
		}
	},
}

func discoverAPIRoutes(root string) {
	fmt.Println("🔍 Scanning for API routes in:", root)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Identify API route files specific to next.js projects old and new
		routeAnalysis.AnalyzeAPIFile(path)
		return nil
	})

	if err != nil {
		fmt.Println("❌ Error scanning:", err)
	}
}

func init() {
	rootCmd.AddCommand(apiCmd)
}
