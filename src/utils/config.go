/*
This file contain the function to extract and parse the config file and
the function to download the remote repository.

TODO: [ ] Expand Config Struct with other value.
	  [x] Check and validate each value, this include also that some value are not mandatory. (e.g there is path of a project and not the url)
	  [x] Function LoadConfigRepo.
*/

package utils

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

var NasConfig *Config
var validate *validator.Validate

type Config struct {
	ProjectPath string `mapstructure:"projectPath" validate:"required,url|dir"`
	OutputPath  string `mapstructure:"outputPath" validate:"omitempty,dir"`
}

func LoadConfig(configPath string) error {
	// Simple reading of the config file
	// Pre :  A STRING type containing the config file path
	// Post : Return a POINTER type to a validate config struct and an error if appears.

	viper.SetConfigFile(configPath)

	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("error reading the config file: %w", err)
	}

	var config Config

	if err := viper.Unmarshal(&config); err != nil {
		return fmt.Errorf("unable to decode the struct of the config file: %w", err)
	}

	validate = validator.New(validator.WithRequiredStructEnabled())

	if err := validate.Struct(&config); err != nil {
		return fmt.Errorf("unable to validate the config file: %w", err)
	}

	NasConfig = &config
	return nil
}

func (config *Config) LoadConfigRepo() error {
	// Parse the config value to get the repo
	// Pre : POINTER to a loaded and validated config struct
	// Post : config.ProjectPath will contain the new path of the project. Return an error if appears.

	if err := validate.Var(config.ProjectPath, "required,dir"); err != nil {
		// If it's remote repository => clone the remote repository inside ./tmp
		// Else do nothing

		fmt.Println("Cloning remote repository", config.ProjectPath)

		destPath := path.Join("./tmp", strings.TrimSuffix(path.Base(config.ProjectPath), ".git")) // Get the name of the repository from the URL.
		if _, err := git.PlainClone(destPath, false, &git.CloneOptions{
			URL:      config.ProjectPath,
			Progress: os.Stdout,
		}); err != nil {
			return fmt.Errorf("unable to clone the remote repository: %w", err)
		}

		config.ProjectPath = destPath
	}

	return nil
}

func IsLoaded() bool {
	return NasConfig != nil
}
