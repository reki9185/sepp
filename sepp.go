package main

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"github.com/yangalan0903/sepp/logger"
	"github.com/yangalan0903/sepp/service"
	"github.com/free5gc/version"
)

var SEPP = &service.SEPP{}

var appLog *logrus.Entry

func init() {
	appLog = logger.AppLog
}

func main() {
	app := cli.NewApp()
	app.Name = "sepp"
	fmt.Print(app.Name, "\n")
	appLog.Infoln("SEPP version: ", version.GetVersion())
	app.Usage = "-free5gccfg common configuration file -seppcfg sepp configuration file"
	app.Action = action
	app.Flags = SEPP.GetCliCmd()
	if err := app.Run(os.Args); err != nil {
		appLog.Errorf("SEPP Run error: %v", err)
	}
}

func action(c *cli.Context) error {
	if err := SEPP.Initialize(c); err != nil {
		logger.CfgLog.Errorf("%+v", err)
		return fmt.Errorf("Failed to initialize !!")
	}

	SEPP.Start()

	return nil
}