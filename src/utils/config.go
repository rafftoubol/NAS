/*
This file contain the function to extract and parse the config file and
the function to download the remote repository.

TODO: - Expand Config Struct with other value.
	  - Check and validate each value, this include also that some value are not mandatory. (e.g there is path of a project and not the url)
	  - Function LoadConfigRepo.
*/

package config

import (
	"fmt"
	"os"

	// with go modules enabled (GO111MODULE=on or outside GOPATH)

	"github.com/go-git/go-git/v5"
	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

type Config struct {
	ProjectPath string `mapstructure:"projectPath" validate:"required,url|dirpath"`
}

func LoadConfig(config_path string) (*Config, error) {
	// Simple reading of the config file
	// Pre :  A STRING type containing the config file path
	// Post : Return a POINTER type to a validate config struct and an error if appears.

	viper.SetConfigFile(config_path)

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("error reading the config file: %w", err)
	}

	var config Config

	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("unable to decode the struct of the config file: %w", err)
	}

	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(&config); err != nil {
		return nil, fmt.Errorf("unable to validate the config file: %w", err)
	}

	return &config, nil
}

func (config *Config) LoadConfigRepo() error {
	// Parse the config value to get the repo
	// Pre : POINTER to a loaded and validated config struct
	// Post : Return an error if appears or nil.

	fmt.Println("git clone", config.ProjectPath)
	_, err := git.PlainClone("./tmp", false, &git.CloneOptions{
		URL:      config.ProjectPath,
		Progress: os.Stdout,
	})

	if err != nil {
		return fmt.Errorf("unable to clone the remote repository: %w", err)
	}

	return nil
}
