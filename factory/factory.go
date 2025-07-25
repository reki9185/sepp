/*
 * SEPP Configuration Factory
 */

package factory

import (
	"fmt"
	"io/ioutil"

	"github.com/yangalan0903/sepp/logger"
	"gopkg.in/yaml.v2"
)

var SeppConfig Config

// TODO: Support configuration update from REST api
func InitConfigFactory(f string) error {
	if content, err := ioutil.ReadFile(f); err != nil {
		return err
	} else {
		SeppConfig = Config{}

		if yamlErr := yaml.Unmarshal(content, &SeppConfig); yamlErr != nil {
			return yamlErr
		}
	}

	return nil
}

func CheckConfigVersion() error {
	currentVersion := SeppConfig.GetVersion()

	if currentVersion != SEPP_EXPECTED_CONFIG_VERSION {
		return fmt.Errorf("config version is [%s], but expected is [%s].",
			currentVersion, SEPP_EXPECTED_CONFIG_VERSION)
	}
	logger.CfgLog.Infof("config version [%s]", currentVersion)

	return nil
}
