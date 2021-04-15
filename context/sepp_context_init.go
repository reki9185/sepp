package context

import (
	"fmt"
	"os"
	"strconv"
	"github.com/google/uuid"

	"github.com/yangalan0903/sepp/factory"
	"github.com/yangalan0903/sepp/logger"
	"github.com/yangalan0903/openapi/models"
	"github.com/free5gc/path_util"
)

func TestInit() {
	// load config
	DefaultSeppConfigPath := path_util.Free5gcPath("free5gc/config/seppcfg.yaml")
	if err := factory.InitConfigFactory(DefaultSeppConfigPath); err != nil {
		panic(err)
	}
	Init()
}

func InitSeppContext(context *SEPPContext) {
	config := factory.SeppConfig
	logger.InitLog.Infof("seppconfig Info: Version[%s] Description[%s]\n", config.Info.Version, config.Info.Description)

	configuration := config.Configuration
	context.NfId = uuid.New().String()
	context.FqdnList = append(context.FqdnList, configuration.fqdnSupportList...)
	sbi := configuration.Sbi
	context.PLMNSecInfo = make(map[FQDN]SecInfo)
	for index := range context.FqdnList {
		var secInfo SecInfo
		context.PLMNSecInfo [context.FqdnList[index]] = secInfo
	}
	context.SupportedSecCapabilityList = append(context.SupportedSecCapabilityList, "TLS")
	context.SupportedSecCapabilityList = append(context.SupportedSecCapabilityList, "PRINS")
	context.NrfUri = configuration.NrfUri
	context.UriScheme = models.UriScheme(configuration.Sbi.Scheme) // default uri scheme
	context.RegisterIPv4 = factory.SEPP_DEFAULT_IPV4               // default localhost
	context.SBIPort = factory.SEPP_DEFAULT_PORT_INT                // default port
	if sbi != nil {
		if sbi.RegisterIPv4 != "" {
			context.RegisterIPv4 = sbi.RegisterIPv4
		}
		if sbi.Port != 0 {
			context.SBIPort = sbi.Port
		}

		if sbi.Scheme == "https" {
			context.UriScheme = models.UriScheme_HTTPS
		} else {
			context.UriScheme = models.UriScheme_HTTP
		}

		context.BindingIPv4 = os.Getenv(sbi.BindingIPv4)
		if context.BindingIPv4 != "" {
			logger.InitLog.Info("Parsing ServerIPv4 address from ENV Variable.")
		} else {
			context.BindingIPv4 = sbi.BindingIPv4
			if context.BindingIPv4 == "" {
				logger.InitLog.Warn("Error parsing ServerIPv4 address as string. Using the 0.0.0.0 address as default.")
				context.BindingIPv4 = "0.0.0.0"
			}
		}
	}

	context.Url = string(context.UriScheme) + "://" + context.RegisterIPv4 + ":" + strconv.Itoa(context.SBIPort)
	context.PlmnList = append(context.PlmnList, configuration.PlmnSupportList...)

	fmt.Println("sepp context = ", context)
}