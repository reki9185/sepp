package producer

import (
	// "context"
	// "crypto/sha256"
	// "encoding/base64"
	// "encoding/hex"
	// "fmt"
	// "math/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"net/http"

	// "strings"
	// "time"

	// "github.com/bronze1man/radius"
	// "github.com/google/gopacket"
	// "github.com/google/gopacket/layers"

	// "github.com/free5gc/UeauCommon"
	"github.com/free5gc/http_wrapper"
	"github.com/yangalan0903/openapi/models"
	sepp_context "github.com/yangalan0903/sepp/context"
	"github.com/yangalan0903/sepp/logger"
	"golang.org/x/crypto/hkdf"
)

func HandleN32fCtxTerminate(request *http_wrapper.Request) *http_wrapper.Response {
	logger.Handshake.Infof("handle PostN32fTerminate")

	n32fContextInfo := request.Body.(models.N32fContextInfo)

	response, problemDetails := N32fCtxTerminateProcedure(n32fContextInfo)

	if response != nil {
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func N32fCtxTerminateProcedure(n32fContextInfo models.N32fContextInfo) (*models.N32fContextInfo,
	*models.ProblemDetails) {
	var responseBody models.N32fContextInfo

	// delete N32fContext
	self := sepp_context.GetSelf()
	remotePlmnId := self.N32fContextPool[n32fContextInfo.N32fContextId].PeerInformation.RemotePlmnId
	delete(self.PLMNSecInfo, remotePlmnId)
	responseBody = models.N32fContextInfo{
		N32fContextId: self.N32fContextPool[n32fContextInfo.N32fContextId].N32fContextId,
	}
	delete(self.N32fContextPool, n32fContextInfo.N32fContextId)

	logger.Handshake.Infof("Delete %s N32fContext", remotePlmnId)

	return &responseBody, nil
}

func HandleExchangeCapability(request *http_wrapper.Request) *http_wrapper.Response {
	logger.Handshake.Infof("handle ExchangeCapability")

	secNegotiateReqData := request.Body.(models.SecNegotiateReqData)

	response, problemDetails := ExchangeCapabilityProcedure(secNegotiateReqData)

	if response != nil {
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func ExchangeCapabilityProcedure(secNegotiateReqData models.SecNegotiateReqData) (*models.SecNegotiateRspData,
	*models.ProblemDetails) {
	var responseBody models.SecNegotiateRspData
	self := sepp_context.GetSelf()
	// verify fqdn
	fqdn := secNegotiateReqData.Sender
	if _, ok := self.FqdnIpMap[fqdn]; !ok {
		logger.Handshake.Infof("fqdn is not supported")
		var problemDetails models.ProblemDetails
		problemDetails.Cause = "fqdn is not supported"
		problemDetails.Status = http.StatusBadRequest
		// TODO return error
		return nil, &problemDetails
	}

	// decide securityCapability
	supportedSecCapabilityList := secNegotiateReqData.SupportedSecCapabilityList
	var securityCapability models.SecurityCapability
	for _, secCap := range supportedSecCapabilityList {
		if secCap == models.SecurityCapability_PRINS {
			securityCapability = secCap
			break
		} else if secCap == models.SecurityCapability_TLS {
			securityCapability = secCap
			// break
		}
	}
	if securityCapability == "" {
		logger.Handshake.Infof("security Capability is not supported")
		var problemDetails models.ProblemDetails
		problemDetails.Cause = "security Capability is not supported"
		problemDetails.Status = http.StatusBadRequest
		return nil, &problemDetails
	}
	var secInfo sepp_context.SecInfo
	secInfo.SecCap = securityCapability
	self.PLMNSecInfo[fqdn] = secInfo

	//TODO verify 3gpp-Sbi-Target-apiRoot HTTP header is supported or not

	responseBody.Sender = self.SelfFqdn
	responseBody.SelectedSecCapability = securityCapability

	return &responseBody, nil
}

func HandleExchangeParams(request *http_wrapper.Request, masterKey []byte) *http_wrapper.Response {
	logger.Handshake.Infof("Handle ExchangeParams\n")

	secParamExchReqData := request.Body.(models.SecParamExchReqData)

	response, problemDetails := ExchangeParamsProcedure(secParamExchReqData, masterKey)

	if response != nil {
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func ExchangeParamsProcedure(secParamExchReqData models.SecParamExchReqData, masterKey []byte) (*models.SecParamExchRspData,
	*models.ProblemDetails) {
	var responseBody models.SecParamExchRspData
	n32fContextId := secParamExchReqData.N32fContextId
	self := sepp_context.GetSelf()

	fqdn := secParamExchReqData.Sender
	var secInfo sepp_context.SecInfo
	if temp, ok := self.PLMNSecInfo[fqdn]; !ok {
		logger.Handshake.Infof("fqdn is not supported", fqdn)
		var problemDetails models.ProblemDetails
		problemDetails.Cause = "fqdn is not supported"
		problemDetails.Status = http.StatusBadRequest
		// TODO return error
		return nil, &problemDetails
	} else {
		secInfo = temp
	}

	if secInfo.N32fContexId == "" { //for Cipher Suite Negotiation
		secInfo.N32fContexId = fmt.Sprintf("%x", rand.Uint64())
		self.PLMNSecInfo[fqdn] = secInfo
		var n32fContext sepp_context.N32fContext
		var cipherSuites sepp_context.CipherSuite
		jweCipherSuiteList := secParamExchReqData.JweCipherSuiteList
		for _, ciphersuite := range jweCipherSuiteList {
			if ciphersuite == "A128GCM" {
				cipherSuites.JweCipherSuite = ciphersuite
				// break
			} else if ciphersuite == "A256GCM" {
				cipherSuites.JweCipherSuite = ciphersuite
				break
			}
		}
		jwsCipherSuiteList := secParamExchReqData.JwsCipherSuiteList
		for _, ciphersuite := range jwsCipherSuiteList {
			if ciphersuite == "ES256" {
				cipherSuites.JwsCipherSuite = ciphersuite
				break
			}
		}
		if cipherSuites.JwsCipherSuite == "" || cipherSuites.JweCipherSuite == "" {
			logger.Handshake.Infof("jws or jwe cipher suite is not supported")
			var problemDetails models.ProblemDetails
			problemDetails.Cause = "jws or jwe cipher suite is not supported"
			problemDetails.Status = http.StatusBadRequest
			return nil, &problemDetails
		}
		var peerInfo sepp_context.N32fPeerInformation
		peerInfo.RemotePlmnId = fqdn
		peerInfo.RemoteSeppAddress, _ = self.FqdnIpMap[fqdn]
		n32fContext.PeerInformation = peerInfo
		var secContext sepp_context.N32fSecContext
		secContext.CipherSuitList = cipherSuites
		n32fContext.SecContext = secContext
		n32fContext.N32fContextId = n32fContextId

		self.N32fContextPool[secInfo.N32fContexId] = n32fContext

		responseBody.N32fContextId = secInfo.N32fContexId
		responseBody.SelectedJweCipherSuite = cipherSuites.JweCipherSuite
		responseBody.SelectedJwsCipherSuite = cipherSuites.JwsCipherSuite
		responseBody.Sender = self.SelfFqdn

		return &responseBody, nil

	} else if secParamExchReqData.ProtectionPolicyInfo != nil {
		keyLen := 0
		switch self.N32fContextPool[secInfo.N32fContexId].SecContext.CipherSuitList.JweCipherSuite {
		case "A128GCM":
			keyLen = 16
		case "A256GCM":
			keyLen = 32
		}
		hash := sha256.New
		info := []byte("N32" + secParamExchReqData.N32fContextId + "parallel_request_key")
		expandHkdf := hkdf.Expand(hash, masterKey, info)
		recvReqKey := make([]byte, keyLen)
		if _, err := io.ReadFull(expandHkdf, recvReqKey); err != nil {
			panic(err)
		}
		hash = sha256.New
		info = []byte("N32" + secParamExchReqData.N32fContextId + "parallel_request_iv_salt")
		expandHkdf = hkdf.Expand(hash, masterKey, info)
		recvReqIv := make([]byte, 8)
		if _, err := io.ReadFull(expandHkdf, recvReqIv); err != nil {
			panic(err)
		}

		hash = sha256.New
		info = []byte("N32" + secParamExchReqData.N32fContextId + "parallel_response_key")
		expandHkdf = hkdf.Expand(hash, masterKey, info)
		recvRspKey := make([]byte, keyLen)
		if _, err := io.ReadFull(expandHkdf, recvRspKey); err != nil {
			panic(err)
		}
		hash = sha256.New
		info = []byte("N32" + secParamExchReqData.N32fContextId + "parallel_response_iv_salt")
		expandHkdf = hkdf.Expand(hash, masterKey, info)
		recvRspIv := make([]byte, 8)
		if _, err := io.ReadFull(expandHkdf, recvRspIv); err != nil {
			panic(err)
		}

		hash = sha256.New
		info = []byte("N32" + secParamExchReqData.N32fContextId + "reverse_request_key")

		expandHkdf = hkdf.Expand(hash, masterKey, info)
		sendReqKey := make([]byte, keyLen)
		if _, err := io.ReadFull(expandHkdf, sendReqKey); err != nil {
			panic(err)
		}
		hash = sha256.New
		info = []byte("N32" + secParamExchReqData.N32fContextId + "reverse_request_iv_salt")
		expandHkdf = hkdf.Expand(hash, masterKey, info)
		sendReqIv := make([]byte, 8)
		if _, err := io.ReadFull(expandHkdf, sendReqIv); err != nil {
			panic(err)
		}

		hash = sha256.New
		info = []byte("N32" + secParamExchReqData.N32fContextId + "reverse_response_key")

		expandHkdf = hkdf.Expand(hash, masterKey, info)
		sendRspKey := make([]byte, keyLen)
		if _, err := io.ReadFull(expandHkdf, sendRspKey); err != nil {
			panic(err)
		}
		hash = sha256.New
		info = []byte("N32" + secParamExchReqData.N32fContextId + "reverse_response_iv_salt")
		expandHkdf = hkdf.Expand(hash, masterKey, info)
		sendRspIv := make([]byte, 8)
		if _, err := io.ReadFull(expandHkdf, sendRspIv); err != nil {
			panic(err)
		}
		n32fContext, _ := self.N32fContextPool[secInfo.N32fContexId]
		n32fContext.SecContext.SessionKeys.SendReqKey = sendReqKey
		n32fContext.SecContext.SessionKeys.SendResKey = sendRspKey
		n32fContext.SecContext.SessionKeys.RecvReqKey = recvReqKey
		n32fContext.SecContext.SessionKeys.RecvResKey = recvRspKey
		n32fContext.SecContext.IVs.SendReqIV = sendReqIv
		n32fContext.SecContext.IVs.SendReqSeq = 0
		n32fContext.SecContext.IVs.SendResIV = sendRspIv
		n32fContext.SecContext.IVs.SendResSeq = 0
		n32fContext.SecContext.IVs.RecvReqIV = recvReqIv
		n32fContext.SecContext.IVs.RecvReqSeq = 0
		n32fContext.SecContext.IVs.RecvResIV = recvRspIv
		n32fContext.SecContext.IVs.RecvResSeq = 0
		n32fContext.SecContext.ProtectionPolicy.ApiIeMappingList = secParamExchReqData.ProtectionPolicyInfo.ApiIeMappingList
		self.N32fContextPool[secInfo.N32fContexId] = n32fContext
		responseBody.N32fContextId = n32fContext.N32fContextId
		responseBody.SelProtectionPolicyInfo = &models.ProtectionPolicy{ApiIeMappingList: self.IPXProtectionPolicy}
		responseBody.Sender = self.SelfFqdn

		return &responseBody, nil
	} else if secParamExchReqData.IpxProviderSecInfoList != nil {
		n32fContext, _ := self.N32fContextPool[secInfo.N32fContexId]
		var ipxSecInfoList []models.IpxProviderSecInfo
		ipxSecInfoList = append(ipxSecInfoList, secParamExchReqData.IpxProviderSecInfoList...)
		// ipxSecInfoList.IpxProviderId = secParamExchReqData.IpxProviderSecInfoList[0].IpxProviderId
		// if rawPublicKeyList := secParamExchReqData.IpxProviderSecInfoList[0].RawPublicKeyList; rawPublicKeyList != nil {
		// 	ipxSecInfo.RawPublicKeyList = append(ipxSecInfo.RawPublicKeyList, rawPublicKeyList...)
		// } else if certificateList := secParamExchReqData.IpxProviderSecInfoList[0].CertificateList; certificateList != nil{
		// 	ipxSecInfo.CertificateList = append(ipxSecInfo.CertificateList, certificateList...)
		// } else {
		// 	logger.Handshake.Infof("secParamExchReqData does not contain any IPX Info")
		// 	var problemDetails models.ProblemDetails
		// 	problemDetails.Cause = "IE_MISSING"
		// 	problemDetails.Status = http.StatusBadRequest
		// 	return nil, &problemDetails
		// }
		n32fContext.SecContext.IPXSecInfo = ipxSecInfoList
		self.N32fContextPool[secInfo.N32fContexId] = n32fContext
		responseBody.N32fContextId = n32fContext.N32fContextId
		responseBody.IpxProviderSecInfoList = append(responseBody.IpxProviderSecInfoList, self.SelfIPXSecInfo)
		responseBody.SelProtectionPolicyInfo = &self.LocalProtectionPolicy
		responseBody.Sender = self.SelfFqdn
		logger.Handshake.Infoln("param exchange finish:%s", self.N32fContextPool)
		return &responseBody, nil
	}
	problemDetails := models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return nil, &problemDetails
}
