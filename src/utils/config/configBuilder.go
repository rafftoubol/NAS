package config

import (
	"fmt"
	"os"
)

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
			CodeScan:         nil,
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
		DefCodeScan(true).
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

func (b *ConfigBuilder) DefCodeScan(codeScan bool) *ConfigBuilder {
	b.config.CodeScan = &codeScan
	/* Debug Printing leaving it incase I need it again
	fmt.Println("b.config.codeScan", b.config.CodeScan)
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
	if b.config.CodeScan == nil {
		defaultValue := false
		b.config.CodeScan = &defaultValue
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
