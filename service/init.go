package service

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/yangalan0903/sepp/consumer"
	sepp_context "github.com/yangalan0903/sepp/context"
	"github.com/yangalan0903/sepp/factory"
	"github.com/yangalan0903/sepp/logger"
	"github.com/yangalan0903/sepp/util"
	"github.com/free5gc/http2_util"
	"github.com/free5gc/logger_util"
	"github.com/yangalan0903/sepp/handshake"
	"github.com/yangalan0903/sepp/JOSEProtectedMessageForwarding"
	"github.com/yangalan0903/sepp/TelescopicFqdnMapping"
	openApiLogger "github.com/free5gc/openapi/logger"
	"github.com/free5gc/path_util"
	pathUtilLogger "github.com/free5gc/path_util/logger"
)

type SEPP struct{}

type (
	// Config information.
	Config struct {
		seppcfg string
	}
)

var config Config

var seppCLi = []cli.Flag{
	cli.StringFlag{
		Name:  "free5gccfg",
		Usage: "common config file",
	},
	cli.StringFlag{
		Name:  "seppcfg",
		Usage: "config file",
	},
}

var initLog *logrus.Entry

func init() {
	initLog = logger.InitLog
}

func (*SEPP) GetCliCmd() (flags []cli.Flag) {
	return seppCLi
}

func (sepp *SEPP) Initialize(c *cli.Context) error {
	config = Config{
		seppcfg: c.String("seppcfg"),
	}

	if config.seppcfg != "" {
		if err := factory.InitConfigFactory(config.seppcfg); err != nil {
			return err
		}
	} else {
		DefaultSeppConfigPath := path_util.Free5gcPath("free5gc/config/seppcfg.yaml")
		if err := factory.InitConfigFactory(DefaultSeppConfigPath); err != nil {
			return err
		}
	}

	sepp.setLogLevel()

	if err := factory.CheckConfigVersion(); err != nil {
		return err
	}

	return nil
}

func ( *SEPP) setLogLevel() {
	if factory.SeppConfig.Logger == nil {
		initLog.Warnln("SEPP config without log level setting!!!")
		return
	}

	if factory.SeppConfig.Logger.AUSF != nil {
		if factory.SeppConfig.Logger.AUSF.DebugLevel != "" {
			if level, err := logrus.ParseLevel(factory.SeppConfig.Logger.AUSF.DebugLevel); err != nil {
				initLog.Warnf("SEPP Log level [%s] is invalid, set to [info] level",
					factory.SeppConfig.Logger.AUSF.DebugLevel)
				logger.SetLogLevel(logrus.InfoLevel)
			} else {
				initLog.Infof("SEPP Log level is set to [%s] level", level)
				logger.SetLogLevel(level)
			}
		} else {
			initLog.Warnln("SEPP Log level not set. Default set to [info] level")
			logger.SetLogLevel(logrus.InfoLevel)
		}
		logger.SetReportCaller(factory.SeppConfig.Logger.AUSF.ReportCaller)
	}

	if factory.SeppConfig.Logger.PathUtil != nil {
		if factory.SeppConfig.Logger.PathUtil.DebugLevel != "" {
			if level, err := logrus.ParseLevel(factory.SeppConfig.Logger.PathUtil.DebugLevel); err != nil {
				pathUtilLogger.PathLog.Warnf("PathUtil Log level [%s] is invalid, set to [info] level",
					factory.SeppConfig.Logger.PathUtil.DebugLevel)
				pathUtilLogger.SetLogLevel(logrus.InfoLevel)
			} else {
				pathUtilLogger.SetLogLevel(level)
			}
		} else {
			pathUtilLogger.PathLog.Warnln("PathUtil Log level not set. Default set to [info] level")
			pathUtilLogger.SetLogLevel(logrus.InfoLevel)
		}
		pathUtilLogger.SetReportCaller(factory.SeppConfig.Logger.PathUtil.ReportCaller)
	}

	if factory.SeppConfig.Logger.OpenApi != nil {
		if factory.SeppConfig.Logger.OpenApi.DebugLevel != "" {
			if level, err := logrus.ParseLevel(factory.SeppConfig.Logger.OpenApi.DebugLevel); err != nil {
				openApiLogger.OpenApiLog.Warnf("OpenAPI Log level [%s] is invalid, set to [info] level",
					factory.SeppConfig.Logger.OpenApi.DebugLevel)
				openApiLogger.SetLogLevel(logrus.InfoLevel)
			} else {
				openApiLogger.SetLogLevel(level)
			}
		} else {
			openApiLogger.OpenApiLog.Warnln("OpenAPI Log level not set. Default set to [info] level")
			openApiLogger.SetLogLevel(logrus.InfoLevel)
		}
		openApiLogger.SetReportCaller(factory.SeppConfig.Logger.OpenApi.ReportCaller)
	}
}

func (sepp *SEPP) FilterCli(c *cli.Context) (args []string) {
	for _, flag := range sepp.GetCliCmd() {
		name := flag.GetName()
		value := fmt.Sprint(c.Generic(name))
		if value == "" {
			continue
		}

		args = append(args, "--"+name, value)
	}
	return args
}

func (sepp *SEPP) Start() {
	initLog.Infoln("Server started")

	router := logger_util.NewGinWithLogrus(logger.GinLog)
	handshake.AddService(router)
	JOSEProtectedMessageForwarding.AddService(router)
	TelescopicFqdnMapping.AddService(router)

	sepp_context.Init()
	self := sepp_context.GetSelf()
	// Register to NRF
	profile, err := consumer.BuildNFInstance(self)
	if err != nil {
		initLog.Error("Build SEPP Profile Error")
	}
	_, self.NfId, err = consumer.SendRegisterNFInstance(self.NrfUri, self.NfId, profile)
	if err != nil {
		initLog.Errorf("SEPP register to NRF Error[%s]", err.Error())
	}

	seppLogPath := util.SeppLogPath

	addr := fmt.Sprintf("%s:%d", self.BindingIPv4, self.SBIPort)

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChannel
		sepp.Terminate()
		os.Exit(0)
	}()

	server, err := http2_util.NewServer(addr, seppLogPath, router)
	if server == nil {
		initLog.Errorf("Initialize HTTP server failed: %+v", err)
		return
	}

	if err != nil {
		initLog.Warnf("Initialize HTTP server: +%v", err)
	}

	serverScheme := factory.SeppConfig.Configuration.Sbi.Scheme
	if serverScheme == "http" {
		err = server.ListenAndServe()
	} else if serverScheme == "https" {
		err = server.ListenAndServeTLS(util.SeppPemPath, util.SeppKeyPath)
	}

	if err != nil {
		initLog.Fatalf("HTTP server setup failed: %+v", err)
	}
}

func (sepp *SEPP) Exec(c *cli.Context) error {
	initLog.Traceln("args:", c.String("seppcfg"))
	args := sepp.FilterCli(c)
	initLog.Traceln("filter: ", args)
	command := exec.Command("./sepp", args...)

	stdout, err := command.StdoutPipe()
	if err != nil {
		initLog.Fatalln(err)
	}
	wg := sync.WaitGroup{}
	wg.Add(3)
	go func() {
		in := bufio.NewScanner(stdout)
		for in.Scan() {
			fmt.Println(in.Text())
		}
		wg.Done()
	}()

	stderr, err := command.StderrPipe()
	if err != nil {
		initLog.Fatalln(err)
	}
	go func() {
		in := bufio.NewScanner(stderr)
		for in.Scan() {
			fmt.Println(in.Text())
		}
		wg.Done()
	}()

	go func() {
		startErr := command.Start()
		if startErr != nil {
			initLog.Fatalln(startErr)
		}
		wg.Done()
	}()

	wg.Wait()

	return err
}

func (sepp *SEPP) Terminate() {
	logger.InitLog.Infof("Terminating SEPP...")
	// deregister with NRF
	// problemDetails, err := consumer.SendDeregisterNFInstance()
	// if problemDetails != nil {
	// 	logger.InitLog.Errorf("Deregister NF instance Failed Problem[%+v]", problemDetails)
	// } else if err != nil {
	// 	logger.InitLog.Errorf("Deregister NF instance Error[%+v]", err)
	// } else {
	// 	logger.InitLog.Infof("Deregister from NRF successfully")
	// }

	logger.InitLog.Infof("SEPP terminated")
}