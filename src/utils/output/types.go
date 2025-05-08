package output

import (
	"attack-surface/src/api"
	"attack-surface/src/scanner"
)

type CombinedResults struct {
	APIs         *api.APIs
	Dependencies *scanner.ScanResult
}
