package server

import (
	"net/http"
	"reflect"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Configuration contains the server configuration.
type Configuration struct {
	Production   bool          `required:"true"`   // if set to true the the server will only respond on 443, otherwise it will respond on the value of DevPort
	DevPort      int           `required:"ignore"` // sets the port that the server will respond to if Production is false, defaults to 8080
	CertFile     string        `required:"ignore"` // sets the directory where the CertFile is stored on the FS
	KeyFile      string        `required:"ignore"` // sets the directories where the KeyFile is stored on the FS
	ReadTimeout  time.Duration `required:"ignore"` // sets the read timeout for the server, defaults to 5
	WriteTimeout time.Duration `required:"ignore"` // sets the write timeout for the server, defaults to 5
	IdleTimeout  time.Duration `required:"ignore"` // sets the idle timeout for the server, defaults to 120
	LogLevel     log.Level     `required:"ignore"` // sets the log level for the server, defaults to Debug
	HTTPServer   *http.Server  `required:"false"`  // this is expected to only be set by the server.go file, however it is exported incase that should change.
	FilesRoot    string        `required:"ignore"` // sets the directory where the static files are stored
}

// NewConfig looks for a file named "config.yaml" in "./" and returns the address to unmarshaled configuration struct.
// Defaults are set here as well. If no config is found environment vars matching the Configuration struct are used.
// If environment vars are not found the defaults are used. If no defaults are found then the nil value of the type is used.
func NewConfig() (*Configuration, error) {
	var configuration *Configuration
	var required []string
	defaults := map[string]interface{}{
		"Production":   false,
		"DevPort":      8080,
		"ReadTimeout":  5,
		"WriteTimeout": 5,
		"IdleTimeout":  120,
		"LogLevel":     log.DebugLevel,
		"FilesRoot":    "./web",
	}

	v := viper.New()
	v.SetConfigType("yaml")                // or viper.SetConfigType("YAML")
	v.AutomaticEnv()                       // will check for an environment variable any time a viper.Get request is made
	v.SetConfigName("config")              // name of config file (without extension)
	v.AddConfigPath("/var/personal-site/") // optionally look for config in /var/personal-site
	v.AddConfigPath(".")                   // optionally look for config in the working directory

	for key, value := range defaults {
		v.SetDefault(key, value)
	}
	// viper.IsSet, which we could otherwise use for determining
	// whether a flag has been supplied, is broken:
	// https://github.com/spf13/viper/pull/331. So we have to proceed
	// by other means.
	isSet := func(flag string) bool {
		return viper.InConfig(flag) || v.IsSet(flag)
	}
	if err := v.ReadInConfig(); err != nil { // Find and read the config file
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired
			log.Infoln("configuration file not found, using defaults and environment vars only")
		} else {
			// Config file was found but another error was produced
			return &Configuration{}, errors.Wrap(err, "config file was found but another error was produced")
		}
	}
	err := v.Unmarshal(&configuration)
	// Set loglevel immediately after unmarshal, which is as soon as I can.
	// I cant figure a better place for this, and have log messages lower than info in this file.
	log.SetLevel(configuration.LogLevel)
	// The whole point of the next 9 lines of code, it to setup the idea of varying levels of
	// require to configuration values. Since somethings (HTTPServer) are never really expected
	// to be configured by a human, but still be passed around, I feel that the user shouldn't
	// care if its set. However a field like Production is important as it changes the fundamental
	// function of the server.
	configurationValue := reflect.ValueOf(*configuration) // get the values of the struct in its post unmarshaled state
	keys := make([]string, configurationValue.NumField()) // use the number of fields in the struct to make a slice
	for index := range keys {
		isExported := configurationValue.Field(index).CanInterface() // check to see if the field is exported to stop a panic
		if isExported {
			keys[index] = configurationValue.Type().Field(index).Name                               // get the field names
			required = append(required, configurationValue.Type().Field(index).Tag.Get("required")) // get the required tags for the field
		}
	}
	for index, key := range keys {
		if !isSet(key) {
			switch required[index] { // since I got the required tags and the field names ar the same time, their indexes should be synced
			case "true":
				return &Configuration{}, errors.Wrapf(err, "required configuration value '%s' has not been set\n", key)
			case "false":
				log.Debugf("a non-required configuration value '%s' has not been set\n", key)
			case "ignore":
				log.Infof("a non-required configuration value '%s' has not been set\n", key)
			}
		}
	}
	log.Debugf("%+v\n", *configuration)
	return configuration, err
}
