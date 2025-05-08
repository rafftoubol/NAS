package apiScanner

import (
	"fmt"
	"os"
	"path/filepath"
)

func DiscoverAPIRoutes(root string) *APIs {
	var allResults APIs

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		result := Scan(path)
		if result != nil {
			allResults.Methods = append(allResults.Methods, result.Methods...)
			allResults.RCE = append(allResults.RCE, result.RCE...)
			allResults.CORS = append(allResults.CORS, result.CORS...)
			allResults.ApiKey = append(allResults.ApiKey, result.ApiKey...)
			allResults.CoomentsSecrets = append(allResults.CoomentsSecrets, result.CoomentsSecrets...)
		}

		return nil
	})

	if err != nil {
		fmt.Println("❌ Error scanning:", err)
		return nil
	}

	if err != nil {
		fmt.Println("❌ Error scanning:", err)
	}

	return &allResults
}
