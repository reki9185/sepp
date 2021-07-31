/*
 * SEPP Configuration Factory
 */

package factory

import (
	"github.com/yangalan0903/openapi/models"
	"github.com/yangalan0903/sepp/logger_util"
)

const (
	SEPP_EXPECTED_CONFIG_VERSION = "1.0.0"
)

type Config struct {
	Info          *Info               `yaml:"info"`
	Configuration *Configuration      `yaml:"configuration"`
	Logger        *logger_util.Logger `yaml:"logger"`
}

type Info struct {
	Version     string `yaml:"version,omitempty"`
	Description string `yaml:"description,omitempty"`
}

const (
	SEPP_DEFAULT_IPV4     = "10.10.0.14"
	SEPP_DEFAULT_PORT     = "8000"
	SEPP_DEFAULT_PORT_INT = 8000
)

type Configuration struct {
	Fqdn            string          `yaml:"fqdn,omitempty"`
	Sbi             *Sbi            `yaml:"sbi,omitempty"`
	FqdnSupportList []FqdnIpMap     `yaml:"fqdnSupportList,omitempty"`
	NrfUri          string          `yaml:"nrfUri,omitempty"`
	IpxUri          string          `yaml:"ipxUri,omitempty"`
	PlmnSupportList []models.PlmnId `yaml:"plmnSupportList,omitempty"`
}

type Sbi struct {
	Scheme       string `yaml:"scheme"`
	RegisterIPv4 string `yaml:"registerIPv4,omitempty"` // IP that is registered at NRF.
	BindingIPv4  string `yaml:"bindingIPv4,omitempty"`  // IP used to run the server in the node.
	iPv4ForN32f  string `yaml:"iPv4ForN32f,omitempty"`
	Port         int    `yaml:"port,omitempty"`
}
type FqdnIpMap struct {
	Fqdn      string `yaml:"fqdn,omitempty"`
	IpForSbi  string `yaml:"ipForSBI,omitempty"`
	IpForN32f string `yaml:"ipForN32f,omitempty"`
}

func (c *Config) GetVersion() string {
	if c.Info != nil && c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}
