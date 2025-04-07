package cli

import (
	"attack-surface/src/api"
	config "attack-surface/src/utils"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
)

var outputPath string
var verbose bool

var apiCmd = &cobra.Command{
	Use:   "api [project_path]",
	Short: "Discovers API routes in the Next.js project",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println("Missing project path argument. Please provide the project path as an argument.")
			os.Exit(1)
		}

		config := config.Config{
			ProjectPath:      args[0],
			OutputPath:       outputPath,
			ApiScan:          true,
			DependenciesScan: false,
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

		// TODO :write to output file.
		var result = api.Scan(path)

		if err != nil {
			fmt.Println(err)
			return nil
		}

		if verbose {
			for _, m := range result.Methods {
				fmt.Printf("⚠️ [Method] %s found in %s at line %d\n \t[Content] %s\n", m.Type, m.Path, m.Line, m.Content)
			}

			for _, m := range result.RCE {
				fmt.Printf("🚨  [Vulnerability] type %s found in %s at line %d\n \t[Content] %s\n", m.Type, m.Path, m.Line, m.Content)
			}

			for _, m := range result.CORS {
				fmt.Printf("🚨  [Vulnerability] type %s found in %s at line %d\n \t[Content] %s\n", m.Type, m.Path, m.Line, m.Content)
			}

			for _, m := range result.ApiKey {
				fmt.Printf("🚨  [Vulnerability] type %s found in %s at line %d\n \t[Content] %s\n", m.Type, m.Path, m.Line, m.Content)
			}

			for _, m := range result.CoomentsSecrets {
				fmt.Printf("🚨  [Vulnerability] type %s found in %s at line %d\n \t[Content] %s\n", m.Type, m.Path, m.Line, m.Content)
			}
		}

		if err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		fmt.Println("❌ Error scanning:", err)
	}
}

func init() {
	apiCmd.Flags().StringVarP(&outputPath, "output", "o", ".", "Output path for the results")
	apiCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output to terminal")
	rootCmd.AddCommand(apiCmd)
}
