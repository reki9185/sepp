package consumer

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"

	"github.com/yangalan0903/openapi/N32_Handshake"
	"github.com/yangalan0903/openapi/models"
	sepp_context "github.com/yangalan0903/sepp/context"
	"golang.org/x/crypto/hkdf"
)

func ExchangeCiphersuite(seppUri string, fqdn string) {
	configuration := N32_Handshake.NewConfiguration()
	configuration.SetBasePath(seppUri)
	client := N32_Handshake.NewAPIClient(configuration)

	self := sepp_context.GetSelf()
	var secParamExchReqData models.SecParamExchReqData
	secParamExchReqData.N32fContextId = fmt.Sprintf("%x", rand.Uint64())
	secParamExchReqData.JweCipherSuiteList = self.JweCipherSuiteList
	secParamExchReqData.JwsCipherSuiteList = self.JwsCipherSuiteList
	secParamExchReqData.Sender = self.SelfFqdn

	var res *http.Response
	for {
		rsp, resTmp, err := client.ParameterExchangeApi.PostExchangeParams(context.TODO(), secParamExchReqData)
		if err != nil || resTmp == nil {
			//TODO : add log
			fmt.Println(fmt.Errorf("SEPP connect to remote sepp Error[%v]", err))
			time.Sleep(2 * time.Second)
			continue
		} else {
			res = resTmp
		}
		status := res.StatusCode
		if status == http.StatusOK {
			secInfo := self.PLMNSecInfo[rsp.Sender]
			secInfo.N32fContexId = secParamExchReqData.N32fContextId
			self.PLMNSecInfo[rsp.Sender] = secInfo
			var n32fContext sepp_context.N32fContext
			var peerInfo sepp_context.N32fPeerInformation
			peerInfo.RemotePlmnId = rsp.Sender
			peerInfo.RemoteSeppAddress = self.FqdnIpMap[rsp.Sender]
			n32fContext.PeerInformation = peerInfo
			var secContext sepp_context.N32fSecContext
			secContext.CipherSuitList.JweCipherSuite = rsp.SelectedJweCipherSuite
			secContext.CipherSuitList.JwsCipherSuite = rsp.SelectedJwsCipherSuite
			keyLen := 0
			switch rsp.SelectedJweCipherSuite {
			case "A128GCM":
				keyLen = 16
			case "A256GCM":
				keyLen = 32
			}
			conText := []byte("")
			masterKey, _ := res.TLS.ExportKeyingMaterial("EXPORTER_3GPP_N32_MASTER", conText, 64)
			hash := sha256.New
			info := []byte("N32" + rsp.N32fContextId + "parallel_request_key")
			expandHkdf := hkdf.Expand(hash, masterKey, info)
			sendReqKey := make([]byte, keyLen)
			if _, err := io.ReadFull(expandHkdf, sendReqKey); err != nil {
				panic(err)
			}
			secContext.SessionKeys.SendReqKey = sendReqKey
			hash = sha256.New
			info = []byte("N32" + rsp.N32fContextId + "parallel_response_key")
			expandHkdf = hkdf.Expand(hash, masterKey, info)
			sendRspKey := make([]byte, keyLen)
			if _, err := io.ReadFull(expandHkdf, sendRspKey); err != nil {
				panic(err)
			}
			secContext.SessionKeys.SendResKey = sendRspKey
			hash = sha256.New
			info = []byte("N32" + rsp.N32fContextId + "reverse_request_key")

			expandHkdf = hkdf.Expand(hash, masterKey, info)
			recvReqKey := make([]byte, keyLen)
			if _, err := io.ReadFull(expandHkdf, recvReqKey); err != nil {
				panic(err)
			}
			secContext.SessionKeys.RecvReqKey = recvReqKey
			hash = sha256.New
			info = []byte("N32" + rsp.N32fContextId + "reverse_response_key")

			expandHkdf = hkdf.Expand(hash, masterKey, info)
			recvResKey := make([]byte, keyLen)
			if _, err := io.ReadFull(expandHkdf, recvResKey); err != nil {
				panic(err)
			}
			secContext.SessionKeys.RecvResKey = recvResKey
			n32fContext.SecContext = secContext
			n32fContext.N32fContextId = rsp.N32fContextId
			self.N32fContextPool[secParamExchReqData.N32fContextId] = n32fContext
			break
		} else {
			fmt.Println(fmt.Errorf("handler returned wrong status code %d", status))
			fmt.Println(fmt.Errorf("remote sepp return wrong status code %d", status))
		}
	}
}

func ExchangeProtectionPolicy(seppUri string, fqdn string) {
	configuration := N32_Handshake.NewConfiguration()
	configuration.SetBasePath(seppUri)
	client := N32_Handshake.NewAPIClient(configuration)

	self := sepp_context.GetSelf()
	var secParamExchReqData models.SecParamExchReqData
	secParamExchReqData.N32fContextId = self.PLMNSecInfo[fqdn].N32fContexId
	secParamExchReqData.ProtectionPolicyInfo = &self.ProtectionPolicy
	secParamExchReqData.Sender = self.SelfFqdn

	var res *http.Response
	for {
		rsp, resTmp, err := client.ParameterExchangeApi.PostExchangeParams(context.TODO(), secParamExchReqData)
		if err != nil || resTmp == nil {
			//TODO : add log
			fmt.Println(fmt.Errorf("SEPP connect to remote sepp Error[%v]", err))
			time.Sleep(2 * time.Second)
			continue
		} else {
			res = resTmp
		}
		status := res.StatusCode
		if status == http.StatusOK {
			n32fContext := self.N32fContextPool[secParamExchReqData.N32fContextId]
			n32fContext.SecContext.ProtectionPolicy = *rsp.SelProtectionPolicyInfo
			self.N32fContextPool[secParamExchReqData.N32fContextId] = n32fContext
			break
		} else {
			fmt.Println(fmt.Errorf("handler returned wrong status code %d", status))
			fmt.Println(fmt.Errorf("remote sepp return wrong status code %d", status))
		}
	}
}

func ExchangeIPXInfo(seppUri string, fqdn string) {
	configuration := N32_Handshake.NewConfiguration()
	configuration.SetBasePath(seppUri)
	client := N32_Handshake.NewAPIClient(configuration)

	self := sepp_context.GetSelf()
	var secParamExchReqData models.SecParamExchReqData
	secParamExchReqData.N32fContextId = self.PLMNSecInfo[fqdn].N32fContexId
	secParamExchReqData.IpxProviderSecInfoList = append(secParamExchReqData.IpxProviderSecInfoList, self.SelfIPXSecInfo)
	secParamExchReqData.Sender = self.SelfFqdn

	var res *http.Response
	for {
		rsp, resTmp, err := client.ParameterExchangeApi.PostExchangeParams(context.TODO(), secParamExchReqData)
		if err != nil || resTmp == nil {
			//TODO : add log
			fmt.Println(fmt.Errorf("SEPP connect to remote sepp Error[%v]", err))
			time.Sleep(2 * time.Second)
			continue
		} else {
			res = resTmp
		}
		status := res.StatusCode
		if status == http.StatusOK {
			n32fContext := self.N32fContextPool[secParamExchReqData.N32fContextId]
			n32fContext.SecContext.IPXSecInfo = append(n32fContext.SecContext.IPXSecInfo, rsp.IpxProviderSecInfoList...)
			self.N32fContextPool[secParamExchReqData.N32fContextId] = n32fContext
			break
		} else {
			fmt.Println(fmt.Errorf("handler returned wrong status code %d", status))
			fmt.Println(fmt.Errorf("remote sepp return wrong status code %d", status))
		}
	}
}
