package dependencyscan

import (
	"attack-surface/src/utils"
	"fmt"
)

type VersionVulns struct {
	NextVersion string
	CVEVulnIDs  []string
}

func checkVersion() {
	var VersionVulns = &VersionVulns{}
	VersionVulns.NextVersion = utils.GlobalNext.Version
	fmt.Println("Next Project Version", VersionVulns.NextVersion)
	
}
