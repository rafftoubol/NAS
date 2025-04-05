package cli

import (
	routeAnalysis "attack-surface/src/route-analysis"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var apiDiscoverCmd = &cobra.Command{
	Use:   "routes-surface",
	Short: "Discovers API routes in the Next.js project",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatalf("Please provide the path")
		}
		discoverAPIRoutes(args[0])
	},
}

func discoverAPIRoutes(root string) {
	fmt.Println("🔍 Scanning for API routes in:", root)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Identify API route files specific to next.js projects old and new
		if !info.IsDir() && (strings.Contains(path, "/pages/api/") || strings.Contains(path, "/app/api/")) {
			fmt.Println("🟢 Found API route:", path)
			routeAnalysis.AnalyzeAPIFile(path)
		}
		return nil
	})

	if err != nil {
		fmt.Println("❌ Error scanning:", err)
	}
}

func init() {
	rootCmd.AddCommand(apiDiscoverCmd)
}
