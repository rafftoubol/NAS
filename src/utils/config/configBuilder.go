package config

/*
File purpose: The purpose of this file is to provide methods for setting the config struct appropriately depending
on the cli options chosen when we dont have a config file. With config file viper handles this, so with cli we must
do so manually.

Usage:
config := NewConfig().
    WithProjectPath(args[0]).
    WithCodeScan(true)
*/

/*
NewConfig This struct takes an input of a config and returns a pointer to a Config struct
*/
func NewConfig() *Config {
	return &Config{
		OutputPath:       ".",
		CodeScan:         false,
		DependenciesScan: false,
	}
}

func (c *Config) WithProjectPath(path string) *Config {
	c.ProjectPath = path
	return c
}

func (c *Config) WithOutputPath(path string) *Config {
	c.OutputPath = path
	return c
}

func (c *Config) WithCodeScan(enabled bool) *Config {
	c.CodeScan = enabled
	return c
}

func (c *Config) WithDependenciesScan(enabled bool) *Config {
	c.DependenciesScan = enabled
	return c

}
