package context

import (
	"fmt"
	"os"
	"strconv"

	"github.com/google/uuid"

	"github.com/free5gc/path_util"
	"github.com/yangalan0903/openapi/models"
	"github.com/yangalan0903/sepp/factory"
	"github.com/yangalan0903/sepp/logger"
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
	context.SelfFqdn = configuration.Fqdn
	context.FqdnIpMap = make(map[FQDN]IpAddress)
	context.PLMNSecInfo = make(map[FQDN]SecInfo)
	for index := range configuration.FqdnSupportList {
		fqdn := configuration.FqdnSupportList[index].Fqdn
		ipForSBI := configuration.FqdnSupportList[index].IpForSbi
		ipForN32f := configuration.FqdnSupportList[index].IpForN32f
		ip := IpAddress{
			IpForN32f: ipForN32f,
			IpForSBI:  ipForSBI,
		}
		context.FqdnIpMap[fqdn] = ip
		var secInfo SecInfo
		context.PLMNSecInfo[fqdn] = secInfo
	}
	sbi := configuration.Sbi
	var ipxProviderSecInfo models.IpxProviderSecInfo
	ipxProviderSecInfo.IpxProviderId = "IPX"
	ipxProviderSecInfo.RawPublicKeyList = append(ipxProviderSecInfo.RawPublicKeyList, "ODU4ODU1NTQxMTQ0NTQwMzkzODc1NTQwNTEwNjAzOTQ3MjgwODU2NTExMTc1MjU4OTkwNjQ4MDQyMDIyNzI1MjU3MjMwOTM5NDkyODUrNzUzNzE0Njc4OTEwMjc2MDE2OTc3MTc2NzQwMzQ0MTg0NjUxMzgzMTczMjg3MTY3MjQxODAwNzEzNTU5NTEwODg0NzgyNzY0ODE5NTc=")
	context.SelfIPXSecInfo = append(context.SelfIPXSecInfo, ipxProviderSecInfo)
	context.N32fContextPool = make(map[N32fContextId]N32fContext)
	context.JweCipherSuiteList = append(context.JweCipherSuiteList, "A128GCM", "A256GCM")
	context.JwsCipherSuiteList = append(context.JwsCipherSuiteList, "ES256")
	context.SupportedSecCapabilityList = append(context.SupportedSecCapabilityList, "TLS")
	context.SupportedSecCapabilityList = append(context.SupportedSecCapabilityList, "PRINS")
	context.NrfUri = configuration.NrfUri
	context.IpxUri = configuration.IpxUri
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

	BuildLocalProtectionPolice(context)
	BuildIpxProtectionPolice(context)
	context.Url = string(context.UriScheme) + "://" + context.RegisterIPv4 + ":" + strconv.Itoa(context.SBIPort)
	context.PlmnList = append(context.PlmnList, configuration.PlmnSupportList...)

	fmt.Println("sepp context = ", context)
}

func BuildLocalProtectionPolice(context *SEPPContext) {
	var apiIeMapping models.ApiIeMapping
	var apiSignature models.ApiSignature
	apiSignature.Uri = "/nnrf-disc/v1/nf-instances"
	apiIeMapping.ApiSignature = apiSignature
	apiIeMapping.ApiMethod = models.HttpMethod_GET
	ieInfo := models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_UEID,
		ReqIe:  "supi",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:        models.IeLocation_URI_PARAM,
		IeType:       models.IeType_NONSENSITIVE,
		ReqIe:        "target-nf-type",
		IsModifiable: true,
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "requester-nf-type",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "service-names",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "requester-nf-instance-fqdn",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "target-plmn-list",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "target-nf-instance-id",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "target-nf-fqdn",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "snssais",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "nsi-list",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "dnn",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "smf-serving-area",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "amf-region-id",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_LOCATION,
		ReqIe:  "tai",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "amf-set-id",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "guami",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "ue-ipv4-address",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "ip-domain",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "ue-ipv6-prefix",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "pgw-ind",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "pgw",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_UEID,
		ReqIe:  "gpsi",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "external-group-identity",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "data-set",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "routing-indicator",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "group-id-list",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_URI_PARAM,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "access-type",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_BODY,
		IeType: models.IeType_NONSENSITIVE,
		RspIe:  "/validityPeriod",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_BODY,
		IeType: models.IeType_NONSENSITIVE,
		RspIe:  "/nfInstances/[0]/nfInstanceId",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_BODY,
		IeType: models.IeType_NONSENSITIVE,
		RspIe:  "/nfInstances/[0]/nfType",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_BODY,
		IeType: models.IeType_NONSENSITIVE,
		RspIe:  "/nfInstances/[0]/nfStatus",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)

	context.LocalProtectionPolicy.ApiIeMappingList = append(context.LocalProtectionPolicy.ApiIeMappingList, apiIeMapping)

	apiIeMapping = models.ApiIeMapping{}
	apiSignature = models.ApiSignature{}
	apiSignature.Uri = "/nausf-auth/v1/ue-authentications"
	apiIeMapping.ApiSignature = apiSignature
	apiIeMapping.ApiMethod = models.HttpMethod_POST
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_BODY,
		IeType: models.IeType_UEID,
		ReqIe:  "/supiOrSuci",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_BODY,
		IeType: models.IeType_AUTHENTICATION_MATERIAL,
		ReqIe:  "/servingNetworkName/rand",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_BODY,
		IeType: models.IeType_AUTHENTICATION_MATERIAL,
		ReqIe:  "/servingNetworkName/auts",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_BODY,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "/traceData/traceRef",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_BODY,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "/traceData/traceDepth",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_BODY,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "/traceData/neTypeList",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_BODY,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "/traceData/eventList",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_BODY,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "/traceData/collectionEntityIpv4Addr",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_BODY,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "/traceData/collectionEntityIpv6Addr",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_BODY,
		IeType: models.IeType_NONSENSITIVE,
		ReqIe:  "/traceData/interfaceList",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)

	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_BODY,
		IeType: models.IeType_NONSENSITIVE,
		RspIe:  "/authType",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_BODY,
		IeType: models.IeType_NONSENSITIVE,
		RspIe:  "/servingNetworkName",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_BODY,
		IeType: models.IeType_AUTHENTICATION_MATERIAL,
		RspIe:  "/5gAuthData",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_BODY,
		IeType: models.IeType_NONSENSITIVE,
		RspIe:  "/_links/link",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_BODY,
		IeType: models.IeType_AUTHENTICATION_MATERIAL,
		RspIe:  "/5gAuthData/rand",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_BODY,
		IeType: models.IeType_AUTHENTICATION_MATERIAL,
		RspIe:  "/5gAuthData/hxresStar",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	ieInfo = models.IeInfo{
		IeLoc:  models.IeLocation_BODY,
		IeType: models.IeType_AUTHENTICATION_MATERIAL,
		RspIe:  "/5gAuthData/autn",
	}
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	context.LocalProtectionPolicy.ApiIeMappingList = append(context.LocalProtectionPolicy.ApiIeMappingList, apiIeMapping)
	context.LocalProtectionPolicy.DataTypeEncPolicy = []models.IeType{
		models.IeType_AUTHENTICATION_MATERIAL,
		models.IeType_AUTHORIZATION_TOKEN,
		models.IeType_KEY_MATERIAL,
		models.IeType_LOCATION,
		models.IeType_UEID,
	}
}

func BuildIpxProtectionPolice(context *SEPPContext) {
	var apiIeMapping models.ApiIeMapping
	var apiSignature models.ApiSignature
	apiSignature.Uri = "/nnrf-disc/v1/nf-instances"
	apiIeMapping.ApiSignature = apiSignature
	apiIeMapping.ApiMethod = models.HttpMethod_GET
	var ieInfo models.IeInfo
	ieInfo.IeLoc = models.IeLocation_URI_PARAM
	ieInfo.IeType = models.IeType_NONSENSITIVE
	ieInfo.ReqIe = "target-nf-type"
	ieInfo.IsModifiable = true
	apiIeMapping.IeList = append(apiIeMapping.IeList, ieInfo)
	apiIeMapping.IeList = append(apiIeMapping.IeList,
		models.IeInfo{
			IeLoc:        models.IeLocation_BODY,
			IeType:       models.IeType_NONSENSITIVE,
			RspIe:        "/nfInstances/[0]/nfServices/[0]/ipEndPoints/[0]/ipv4Address",
			IsModifiable: true,
		},
	)
	apiIeMapping.IeList = append(apiIeMapping.IeList,
		models.IeInfo{
			IeLoc:        models.IeLocation_HEADER,
			IeType:       models.IeType_NONSENSITIVE,
			RspIe:        "Content-Type",
			IsModifiable: true,
		},
	)
	context.IPXProtectionPolicy = append(context.IPXProtectionPolicy, apiIeMapping)
}
