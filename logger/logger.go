package logger

import (
	"os"
	"time"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/logger_conf"
	"github.com/free5gc/logger_util"
)

var (
	log                 *logrus.Logger
	AppLog              *logrus.Entry
	InitLog             *logrus.Entry
	CfgLog              *logrus.Entry
	N32fTerminate       *logrus.Entry
	ExchangeCapability  *logrus.Entry
	EapAuthComfirmLog   *logrus.Entry
	HandlerLog          *logrus.Entry
	ContextLog          *logrus.Entry
	ConsumerLog         *logrus.Entry
	GinLog              *logrus.Entry
)

func init() {
	log = logrus.New()
	log.SetReportCaller(false)

	log.Formatter = &formatter.Formatter{
		TimestampFormat: time.RFC3339,
		TrimMessages:    true,
		NoFieldsSpace:   true,
		HideKeys:        true,
		FieldsOrder:     []string{"component", "category"},
	}

	free5gcLogHook, err := logger_util.NewFileHook(logger_conf.Free5gcLogFile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o666)
	if err == nil {
		log.Hooks.Add(free5gcLogHook)
	}

	selfLogHook, err := logger_util.NewFileHook(logger_conf.NfLogDir+"sepp.log", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o666)
	if err == nil {
		log.Hooks.Add(selfLogHook)
	}

	AppLog = log.WithFields(logrus.Fields{"component": "SEPP", "category": "App"})
	InitLog = log.WithFields(logrus.Fields{"component": "SEPP", "category": "Init"})
	CfgLog = log.WithFields(logrus.Fields{"component": "SEPP", "category": "CFG"})
	// HandShakeLog = log.WithFields(logrus.Fields{"component": "SEPP", "category": "HandShakeLog"})
	// JOSEProtectLog = log.WithFields(logrus.Fields{"component": "SEPP", "category": "JOSEProtectLog"})
	// FQDNMapping = log.WithFields(logrus.Fields{"component": "SEPP", "category": "FQDNMapping"})
	HandlerLog = log.WithFields(logrus.Fields{"component": "SEPP", "category": "Handler"})
	ContextLog = log.WithFields(logrus.Fields{"component": "SEPP", "category": "ctx"})
	ConsumerLog = log.WithFields(logrus.Fields{"component": "SEPP", "category": "Consumer"})
	GinLog = log.WithFields(logrus.Fields{"component": "SEPP", "category": "GIN"})
}

func SetLogLevel(level logrus.Level) {
	log.SetLevel(level)
}

func SetReportCaller(set bool) {
	log.SetReportCaller(set)
}
