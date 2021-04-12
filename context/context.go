package context

import (
	"regexp"
	"sync"

	"bitbucket.org/alanyang0903/sepp/logger"
	"github.com/free5gc/openapi/models"
)

type SEPPContext struct {

}

type SeppUeContext struct {
}

// Attribute Types for EAP-AKA'
const (
	AT_RAND_ATTRIBUTE         = 1
	AT_AUTN_ATTRIBUTE         = 2
	AT_RES_ATTRIBUTE          = 3
	AT_MAC_ATTRIBUTE          = 11
	AT_NOTIFICATION_ATTRIBUTE = 12
	AT_IDENTITY_ATTRIBUTE     = 14
	AT_KDF_INPUT_ATTRIBUTE    = 23
	AT_KDF_ATTRIBUTE          = 24
)

var seppContext SEPPContext

func Init() {
	if snRegex, err := regexp.Compile("5G:mnc[0-9]{3}[.]mcc[0-9]{3}[.]3gppnetwork[.]org"); err != nil {
		logger.ContextLog.Warnf("SN compile error: %+v", err)
	} else {
		seppContext.snRegex = snRegex
	}
	InitSeppContext(&seppContext)
}

func GetSelf() *AUSFContext {
	return &ausfContext
}

func (a *AUSFContext) GetSelfID() string {
	return a.NfId
}
