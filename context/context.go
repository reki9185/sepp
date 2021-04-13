package context

import (
	// "regexp"
	// "sync"

	// "github.com/yangalan0903/sepp/logger"
	"github.com/yangalan0903/sepp/models"
)

type SEPPContext struct {
	FQDN                       string
	PLMNSecInfo                map[string]SecInfo
	SupportedSecCapabilityList []models.SecurityCapability
	SBIPort                    int
	RegisterIPv4               string
	BindingIPv4                string
	Url                        string
	UriScheme                  models.UriScheme 
	NrfUri                     string
	NfService                  map[models.ServiceName]models.NfService
	PlmnList                   []models.PlmnId
}

type SecInfo struct {
	models.SecurityCapability
	
}

var seppContext SEPPContext

func Init() {
	InitSeppContext(&seppContext)
}

func GetSelf() *SEPPContext {
	return &seppContext
}

func (a *SEPPContext) GetSelfID() string {
	return a.NfId
}
