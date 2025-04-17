package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

/*
	This file contain the methods to get information about the Next.js Project.
*/

type Next struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	Scripts         map[string]string `json:"scripts"`
}

var GlobalNext *Next

func InitNext(projectPath string) (*Next, error) {
	// Create a Next Object Containing the most important information about the project.
	var packagePath string

	// https://godocs.io/path/filepath#WalkDir
	err := filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Base(path) == "package.json" {
			packagePath = path
			return errors.New("found")
		}
		return nil
	})

	if err == nil {
		return nil, fmt.Errorf("Package.json not found ")
	}

	if err.Error() != "found" {
		return nil, fmt.Errorf("Error while reading the directory: %w ", err)
	}

	data, err := os.ReadFile(packagePath)
	if err != nil {
		return nil, fmt.Errorf("Error opening package.json: %w ", err)
	}

	var next Next

	if err := json.Unmarshal(data, &next); err != nil {
		return nil, fmt.Errorf("Error reading package.json: %w ", err)
	}

	if next.Dependencies["next"] == "" {
		return nil, fmt.Errorf("Next.js not found ")
	}

	//fmt.Println("dependencies:", next.Dependencies)
	//fmt.Println("devDependencies:", next.DevDependencies)

	return &next, nil
}
