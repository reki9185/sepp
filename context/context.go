package context

import (
	"sync"

	"github.com/yangalan0903/openapi/models"
)

type FQDN = string
type IpAddress = string
type N32fContextId = string //('^[A-Fa-f0-9]{16}$')
type SEPPContext struct {
	SelfFqdn                   FQDN
	FqdnIpMap                  map[FQDN]IpAddress
	SelfIPXSecInfo             []models.IpxProviderSecInfo
	JweCipherSuiteList         []string
	JwsCipherSuiteList         []string
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
	N32fContextPool            map[N32fContextId]N32fContext
	LocalProtectionPolicy      models.ProtectionPolicy
	IPXProtectionPolicy        []models.ApiIeMapping
	MessagePool                sync.Map
}

type N32fContext struct {
	N32fContextId   N32fContextId
	PeerInformation N32fPeerInformation
	SecContext      N32fSecContext
	Validity        bool
}

type N32fPeerInformation struct {
	RemotePlmnId      FQDN
	RemoteSeppAddress string
}

type N32fSecContext struct {
	SessionKeys      SessionKeyList
	CipherSuitList   CipherSuite
	ProtectionPolicy models.ProtectionPolicy
	Counters         string
	IVs              IvList
	IPXSecInfo       []models.IpxProviderSecInfo
}

type IvList struct {
	SendReqIV  []byte
	SendReqSeq uint32
	SendResIV  []byte
	SendResSeq uint32
	RecvReqIV  []byte
	RecvReqSeq uint32
	RecvResIV  []byte
	RecvResSeq uint32
}
type SessionKeyList struct {
	SendReqKey []byte
	SendResKey []byte
	RecvReqKey []byte
	RecvResKey []byte
}

type CipherSuite struct {
	JweCipherSuite string
	JwsCipherSuite string
}
type SecInfo struct {
	SecCap                           models.SecurityCapability
	N32fContexId                     string
	Var3GppSbiTargetApiRootSupported bool
}

var seppContext SEPPContext

func Init() {
	InitSeppContext(&seppContext)
}

func GetSelf() *SEPPContext {
	return &seppContext
}
