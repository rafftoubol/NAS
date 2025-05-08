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

type Config struct {
	ProjectPath      string `mapstructure:"projectPath" validate:"required,url|dir"`
	OutputPath       string `mapstructure:"outputPath" validate:"omitempty,dir"`
	ApiScan          *bool  `mapstructure:"apiScan" validate:"omitempty,boolean"`
	DependenciesScan *bool  `mapstructure:"dependenciesScan" validate:"omitempty,boolean"`
}

// ConfigBuilder We need to be able to specify default config values easily,
type ConfigBuilder struct {
	config *Config
}

/*
NewConfigBuilder This struct takes an input of a config and returns a pointer to a Config struct
*/
func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{
		config: &Config{
			OutputPath:       ".",
			ApiScan:          nil,
			DependenciesScan: nil,
			//whatever other default values you want to set
		},
	}
}

/*
Each of these functions are used to set the default values of the config struct
Preconditions:
  - The ConfigBuilder struct is initialized
    The function takes a string as an argument,
    which is the name of the field to set the default value for

Postconditions:
  - The ConfigBuilder struct is updated with the default values
    The function returns a pointer to the ConfigBuilder struct

Usage:
1. Inside the function your calling, inside where you call your config you specify Def...(CLI ARG OR Concrete value)
2. then you use withdefaults() which sets any configs not specified to false.
3. Build()

e.g.

	config, _ := config.NewConfigBuilder().
		DefProjectPath(args[0]).
		DefApiScan(true).
		WithDefaults().
		Build()

To be honest I just realised a cleaner way to do this, next week I will refactor again because its not so important
*/
func (b *ConfigBuilder) DefProjectPath(projectPath string) *ConfigBuilder {
	b.config.ProjectPath = projectPath
	return b
}

func (b *ConfigBuilder) DefOutputPath(outputPath string) *ConfigBuilder {
	b.config.OutputPath = "."
	return b
}

func (b *ConfigBuilder) DefApiScan(apiScan bool) *ConfigBuilder {
	b.config.ApiScan = &apiScan
	/* Debug Printing leaving it incase I need it again
	fmt.Println("b.config.apiScan", b.config.ApiScan)
	fmt.Println("ApiImTrue")
	*/
	return b
}

func (b *ConfigBuilder) DefDependenciesScan(dependenciesScan bool) *ConfigBuilder {
	b.config.DependenciesScan = &dependenciesScan
	/* Debug Printing leaving it incase I need it again
	fmt.Println("b.config.depScan", b.config.DependenciesScan)
	fmt.Println("DepImTrue")
	*/
	return b

}

//Add more methods here as we add more config options

func (b *ConfigBuilder) WithDefaults() *ConfigBuilder {
	if b.config.OutputPath == "" {
		b.config.OutputPath = "."
	}
	if b.config.ApiScan == nil {
		defaultValue := false
		b.config.ApiScan = &defaultValue
	}
	if b.config.DependenciesScan == nil {
		defaultValue := false
		b.config.DependenciesScan = &defaultValue
	}
	return b
}

func (b *ConfigBuilder) Build() (*Config, error) {
	if err := b.config.Validate(); err != nil {
		fmt.Println("🛑", err.Error())
		os.Exit(1)
	}
	return b.config, nil
}

func LoadConfigFile(configPath string) (*Config, error) {
	// Simple reading of the config file
	// Pre :  A STRING type containing the config file path
	// Post : Return a POINTER type to a validate config struct and an error if appears.

	viper.SetConfigFile(configPath)
	viper.SetDefault("OutputPath", ".")
	viper.SetDefault("ApiScan", true)
	viper.SetDefault("DependenciesScan", true)

	logrus.Info("Loading config from:", configPath)

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
	// Post : config.ProjectPath will contain the new path of the project. Return an error if appears.

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

	logrus.Debugf("Options Loaded: ProjectPath: %s, OutputPath: %s, API Scan Enabled: %v, Dependencies Scan Enabled: %v",
		c.ProjectPath, c.OutputPath, *c.ApiScan, *c.DependenciesScan)

	// Expand with future cong Options
	return nil
}

func (c *Config) Validate() error {
	validate := validator.New(validator.WithRequiredStructEnabled())

	if err := validate.Struct(c); err != nil {
		return fmt.Errorf("Unable to validate the config file: %w ", err)
	}
	logrus.Debugln("Input fields validated")
	return nil
}
