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
	"github.com/sirupsen/logrus"
	"os"
	"path"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

var NasConfig *Config

type Config struct {
	ProjectPath      string `mapstructure:"projectPath" validate:"required,url|dir"`
	OutputPath       string `mapstructure:"outputPath" validate:"omitempty,dir"`
	ApiScan          bool   `mapstructure:"apiScan" validate:"omitempty,boolean"`
	DependenciesScan bool   `mapstructure:"dependenciesScan" validate:"omitempty,boolean"`
}

func LoadConfig(configPath string) error {
	// Simple reading of the config file
	// Pre :  A STRING type containing the config file path
	// Post : Return a POINTER type to a validate config struct and an error if appears.

	viper.SetConfigFile(configPath)
	viper.SetDefault("OutputPath", ".")
	viper.SetDefault("ApiScan", true)
	viper.SetDefault("DependenciesScan", true)

	logrus.Info("Loading config from:", configPath)

	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("Error reading the config file: %w ", err)
	}

	var config Config

	if err := viper.Unmarshal(&config); err != nil {
		return fmt.Errorf("Unable to decode the struct of the config file: %w ", err)
	}

	if err := config.Validate(); err != nil {
		return fmt.Errorf(err.Error())
	}

	NasConfig = &config
	return nil
}

func (config *Config) LoadConfigRepo() error {
	// Parse the config value to get the repo
	// Pre : POINTER to a loaded and validated config struct
	// Post : config.ProjectPath will contain the new path of the project. Return an error if appears.

	validate := validator.New(validator.WithRequiredStructEnabled())

	if err := validate.Var(config.ProjectPath, "required,dir"); err != nil {
		// If it's remote repository => clone the remote repository inside ./tmp
		// Else do nothing

		logrus.Infof("Cloning remote repository %s", config.ProjectPath)

		destPath := path.Join("./tmp", strings.TrimSuffix(path.Base(config.ProjectPath), ".git")) // Get the name of the repository from the URL.
		if _, err := git.PlainClone(destPath, false, &git.CloneOptions{
			URL:      config.ProjectPath,
			Progress: os.Stdout,
		}); err != nil {
			if err.Error() != "repository already exists" {
				return fmt.Errorf("Unable to clone the remote repository: %w ", err)
			}
			logrus.Warn("Repository already present")

		}

		config.ProjectPath = destPath
	}

	logrus.Debugf("Options Loaded: ProjectPath: %s, OutputPath: %s, API Scan Enabled: %v, Dependencies Scan Enabled: %v",
		config.ProjectPath, config.OutputPath, config.ApiScan, config.DependenciesScan)

	// Expand with future cong Options
	return nil
}

func (config *Config) Validate() error {
	validate := validator.New(validator.WithRequiredStructEnabled())

	if err := validate.Struct(config); err != nil {
		return fmt.Errorf("Unable to validate the config file: %w ", err)
	}
	logrus.Debugln("Input fields validated")
	return nil
}
