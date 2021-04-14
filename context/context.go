package context

import (
	// "regexp"
	// "sync"

	// "github.com/yangalan0903/sepp/logger"
	"github.com/yangalan0903/sepp/models"
)
type FQDN = string
type SEPPContext struct {
	PLMNSecInfo                map[FQDN]SecInfo
	NfId                       string
	SupportedSecCapabilityList []models.SecurityCapability
	SBIPort                    int
	RegisterIPv4               string
	BindingIPv4                string
	Url                        string
	UriScheme                  models.UriScheme 
	NrfUri                     string
	PlmnList                   []models.PlmnId
}

type SecInfo struct {
	secCap models.SecurityCapability
	
}

var seppContext SEPPContext

func Init() {
	InitSeppContext(&seppContext)
}

func GetSelf() *SEPPContext {
	return &seppContext
}

// func (a *SEPPContext) GetSelfID() string {
// 	return a.NfId
// }
