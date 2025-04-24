package main

import (
	cli "attack-surface/src/cli"
)

func main() {
	cli.Execute()
	/*
		err := scanner.Scanner(utils.GlobalNext.Dependencies)
		if err != nil {
			return
		}
		err = scanner.Scanner(utils.GlobalNext.DevDependencies)
		if err != nil {
			return
		}
	*/
}
