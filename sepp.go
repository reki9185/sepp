package main

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"bitbucket.org/alanyang0903/sepp/src/initialize_sepp/logger"
	"bitbucket.org/alanyang0903/sepp/src/initialize_sepp/service"
	"github.com/free5gc/version"
)

var AUSF = &service.AUSF{}

var appLog *logrus.Entry

func init() {
	appLog = logger.AppLog
}

func main() {
	app := cli.NewApp()
	app.Name = "ausf"
	fmt.Print(app.Name, "\n")
	appLog.Infoln("AUSF version: ", version.GetVersion())
	app.Usage = "-free5gccfg common configuration file -ausfcfg ausf configuration file"
	app.Action = action
	app.Flags = AUSF.GetCliCmd()
	if err := app.Run(os.Args); err != nil {
		appLog.Errorf("AUSF Run error: %v", err)
	}
}

func action(c *cli.Context) error {
	if err := AUSF.Initialize(c); err != nil {
		logger.CfgLog.Errorf("%+v", err)
		return fmt.Errorf("Failed to initialize !!")
	}

	AUSF.Start()

	return nil
}