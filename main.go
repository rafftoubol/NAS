package main

import (
	cli "attack-surface/src/cli"
)

func main() {
	cli.Execute()
	/* EXAMPLE USAGE OF FETCH CVES
		TO DO: Proper integration into main
	if CVEs, err := utils.FetchCVE("https://cve.circl.lu/api/search/vercel/next.js"); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(CVEs)
	}
	*/
}
