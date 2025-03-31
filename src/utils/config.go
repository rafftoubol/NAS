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

	"github.com/spf13/viper"
)

type Config struct {
	Url string `mapstructure:"url"`
}

func LoadConfig(config_path string) (*Config, error) {
	// Simple reading of the config file
	// Pre : config_path STRING
	// Post : return Config Struct and error if an error appear.

	viper.SetConfigFile(config_path)

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("error reading the config file : %w", err)
	}

	var config Config

	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("unable to decode the struct of the config file : %w", err)
	}

	return &config, nil
}

func LoadConfigRepo(config Config) (string, error) {
	// Parse the config value to get the repo
	// Pre : the loaded config Struct
	// Post : the path of the repo downloaded and the error if any error appear

	return "", nil
}
