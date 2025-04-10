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

type Config struct {
	ProjectPath      string `mapstructure:"projectPath" validate:"required,url|dir"`
	OutputPath       string `mapstructure:"outputPath" validate:"omitempty,dir"`
	ApiScan          *bool  `mapstructure:"apiScan" validate:"omitempty,boolean"`
	DependenciesScan *bool  `mapstructure:"dependenciesScan" validate:"omitempty,boolean"`
}

// We need to be able to specify default config values easily,
// We can use viper for that however
type ConfigBuilder struct {
	config *Config
}

/*
This struct takes an input of a config and returns a pointer to a Config struct
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
	b.config.ApiScan = true
	return b
}

func (b *ConfigBuilder) DefDependenciesScan(dependenciesScan bool) *ConfigBuilder {
	b.config.DependenciesScan = true
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

func LoadConfig(configPath string) error {
	// Simple reading of the config file
	// Pre :  A STRING type containing the config file path
	// Post : Return a POINTER type to a validate config struct and an error if appears.

	viper.SetConfigFile(configPath)
	viper.SetDefault("OutputPath", ".")
	viper.SetDefault("ApiScan", true)
	viper.SetDefault("DependenciesScan", true)

	fmt.Println("Loading config from:", configPath)

	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("error reading the config file: %w", err)
	}

	var config Config

	if err := viper.Unmarshal(&config); err != nil {
		return fmt.Errorf("unable to decode the struct of the config file: %w", err)
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

		fmt.Println("🔄 Cloning remote repository", config.ProjectPath)

		destPath := path.Join("./tmp", strings.TrimSuffix(path.Base(config.ProjectPath), ".git")) // Get the name of the repository from the URL.
		if _, err := git.PlainClone(destPath, false, &git.CloneOptions{
			URL:      config.ProjectPath,
			Progress: os.Stdout,
		}); err != nil {
			if err.Error() != "repository already exists" {
				return fmt.Errorf("unable to clone the remote repository: %w", err)
			}
			fmt.Println("\t- Repository already present")

		}

		config.ProjectPath = destPath
	}

	fmt.Println("\033[31m" + `Options` + "\033[0m")
	fmt.Println("📁 ProjectPath:", config.ProjectPath)
	fmt.Println("📂 OutputPath:", config.OutputPath)
	fmt.Println("🔗 API Scan Enabled:", config.ApiScan)
	fmt.Println("📔 Dependencies Scan Enabled:", config.DependenciesScan)
	// Expand with future cong Options
	return nil
}

func (config *Config) Validate() error {
	validate := validator.New(validator.WithRequiredStructEnabled())

	if err := validate.Struct(config); err != nil {
		return fmt.Errorf("unable to validate the config file: %w", err)
	}
	fmt.Println("✅  Input fields validated")
	return nil
}
