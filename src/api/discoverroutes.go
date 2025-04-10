package api

import (
	"fmt"
	"os"
	"path/filepath"
)

func DiscoverAPIRoutes(root string) {
	fmt.Println("🔍 Scanning for API routes in:", root)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// TODO :write to output file.
		var result = Scan(path)

		if err != nil {
			fmt.Println(err)
			return nil
		}

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
		
		if err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		fmt.Println("❌ Error scanning:", err)
	}
}
