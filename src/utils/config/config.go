/*
This file contain the function to extract and parse the config file and
the function to download the remote repository.

TODO: [ ] Expand Config Struct with other value.
	  [x] Check and validate each value, this include also that some value are not mandatory. (e.g there is path of a project and not the url)
	  [x] Function LoadConfigRepo.
*/

package config

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

type Config struct {
	ProjectPath      string `mapstructure:"projectPath" validate:"required,url|dir"`
	OutputPath       string `mapstructure:"outputPath" validate:"omitempty,filepath"`
	CodeScan         bool   `mapstructure:"codeScan" validate:"omitempty,boolean"`
	DependenciesScan bool   `mapstructure:"dependenciesScan" validate:"omitempty,boolean"`
}

func LoadConfigFile(configPath string) (*Config, error) {
	// Simple reading of the config file
	// Pre :  A STRING type containing the config file path
	// Post : Return a POINTER type to a validate config struct and an error if appears.

	viper.SetConfigFile(configPath)
	viper.SetDefault("OutputPath", "./report.pdf")
	viper.SetDefault("CodeScan", true)
	viper.SetDefault("DependenciesScan", true)

	logrus.Info("Loading config from: ", configPath)

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("Error reading the config file: %w ", err)
	}

	var config Config

	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("Unable to decode the struct of the config file: %w ", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf(err.Error())
	}
	return &config, nil
}

func (c *Config) LoadConfigRepo() error {
	// Parse the config value to get the repo
	// Pre : POINTER to a loaded and validated config struct
	// Post : config.WithProjectPath will contain the new path of the project. Return an error if appears.

	validate := validator.New(validator.WithRequiredStructEnabled())

	if err := validate.Var(c.ProjectPath, "required,dir"); err != nil {
		// If it's remote repository => clone the remote repository inside ./tmp
		// Else do nothing

		logrus.Infof("Cloning remote repository %s", c.ProjectPath)

		destPath := path.Join("./tmp", strings.TrimSuffix(path.Base(c.ProjectPath), ".git")) // Get the name of the repository from the URL.
		if _, err := git.PlainClone(destPath, false, &git.CloneOptions{
			URL:      c.ProjectPath,
			Progress: os.Stdout,
		}); err != nil {
			if err.Error() != "repository already exists" {
				return fmt.Errorf("Unable to clone the remote repository: %w ", err)
			}
			logrus.Warn("Repository already present")

		}

		c.ProjectPath = destPath
	}

	return nil
}

func (c *Config) Validate() error {
	validate := validator.New(validator.WithRequiredStructEnabled())

	if err := validate.Struct(c); err != nil {
		return fmt.Errorf("Unable to validate the config file: %w ", err)
	}

	// Check if the report file is .pdf
	if strings.ToLower(filepath.Ext(c.OutputPath)) != ".pdf" {
		return fmt.Errorf("Unable to validate the config file: report path must be a pdf file")
	}
	logrus.Debugln("Input fields validated")
	return nil
}
