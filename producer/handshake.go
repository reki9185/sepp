package producer

import (
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"

	"github.com/free5gc/http_wrapper"
	"github.com/yangalan0903/openapi/models"
	"github.com/yangalan0903/sepp/consumer"
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
	if securityCapability == models.SecurityCapability_TLS {
		secInfo.Var3GppSbiTargetApiRootSupported = secNegotiateReqData.Var3GppSbiTargetApiRootSupported
	}
	self.PLMNSecInfo[fqdn] = secInfo

	responseBody.Sender = self.SelfFqdn
	responseBody.SelectedSecCapability = securityCapability
	if securityCapability == models.SecurityCapability_TLS {
		responseBody.Var3GppSbiTargetApiRootSupported = true
	}

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
		return nil, &problemDetails
	} else {
		secInfo = temp
	}

	if secInfo.N32fContexId == "" { //for Cipher Suite Negotiation
		for {
			n32fContextId := fmt.Sprintf("%x", rand.Uint64())
			if _, exist := self.N32fContextPool[n32fContextId]; !exist {
				secInfo.N32fContexId = n32fContextId
				break
			}
		}
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
		peerInfo.RemoteSeppAddress = self.FqdnIpMap[fqdn].IpForN32f
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
		info = []byte("N32" + secInfo.N32fContexId + "reverse_request_key")

		expandHkdf = hkdf.Expand(hash, masterKey, info)
		sendReqKey := make([]byte, keyLen)
		if _, err := io.ReadFull(expandHkdf, sendReqKey); err != nil {
			panic(err)
		}
		hash = sha256.New
		info = []byte("N32" + secInfo.N32fContexId + "reverse_request_iv_salt")
		expandHkdf = hkdf.Expand(hash, masterKey, info)
		sendReqIv := make([]byte, 8)
		if _, err := io.ReadFull(expandHkdf, sendReqIv); err != nil {
			panic(err)
		}

		hash = sha256.New
		info = []byte("N32" + secInfo.N32fContexId + "reverse_response_key")

		expandHkdf = hkdf.Expand(hash, masterKey, info)
		sendRspKey := make([]byte, keyLen)
		if _, err := io.ReadFull(expandHkdf, sendRspKey); err != nil {
			panic(err)
		}
		hash = sha256.New
		info = []byte("N32" + secInfo.N32fContexId + "reverse_response_iv_salt")
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
		n32fContext.SecContext.ProtectionPolicy = *secParamExchReqData.ProtectionPolicyInfo
		self.N32fContextPool[secInfo.N32fContexId] = n32fContext
		responseBody.N32fContextId = n32fContext.N32fContextId
		responseBody.SelProtectionPolicyInfo = &self.LocalProtectionPolicy
		responseBody.Sender = self.SelfFqdn

		return &responseBody, nil
	} else if secParamExchReqData.IpxProviderSecInfoList != nil {
		n32fContext, _ := self.N32fContextPool[secInfo.N32fContexId]
		var ipxSecInfoList []models.IpxProviderSecInfo
		ipxSecInfoList = append(ipxSecInfoList, secParamExchReqData.IpxProviderSecInfoList...)
		n32fContext.SecContext.IPXSecInfo = ipxSecInfoList
		self.N32fContextPool[secInfo.N32fContexId] = n32fContext
		responseBody.N32fContextId = n32fContext.N32fContextId
		responseBody.IpxProviderSecInfoList = append(responseBody.IpxProviderSecInfoList, self.SelfIPXSecInfo...)
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

func HandleN32fErrorReport(request *http_wrapper.Request) *http_wrapper.Response {
	logger.Handshake.Infof("handle PostN32fTerminate")

	n32fErrorInfo := request.Body.(models.N32fErrorInfo)

	problemDetails := N32fErrorReportProcedure(n32fErrorInfo)

	if problemDetails == nil {
		return http_wrapper.NewResponse(http.StatusNoContent, nil, nil)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func N32fErrorReportProcedure(n32fErrorInfo models.N32fErrorInfo) *models.ProblemDetails {

	var request http.Request
	self := sepp_context.GetSelf()
	if value, ok := self.MessagePool.Load(n32fErrorInfo.N32fMessageId); !ok {
		return nil
	} else {
		request = value.(http.Request)
	}
	sbiTargetApiRoot := request.Header.Get("3gpp-Sbi-Target-apiRoot")
	temp := strings.Split(sbiTargetApiRoot, "://")
	temp = strings.Split(temp[1], ":")
	plmnId := temp[0]
	remoteSeppAddr := self.FqdnIpMap[plmnId].IpForSBI
	plmnSecInfo := self.PLMNSecInfo[plmnId]
	n32fContext := self.N32fContextPool[plmnSecInfo.N32fContexId]
	go func() {
		consumer.SendN32fContextTerminate(remoteSeppAddr, n32fContext.PeerInformation.RemotePlmnId, models.N32fContextInfo{N32fContextId: n32fContext.N32fContextId})
		capability, ok := consumer.SendExchangeCapability(remoteSeppAddr)
		if !ok {
			return
		}
		if *capability == models.SecurityCapability_PRINS {
			consumer.ExchangeCiphersuite(remoteSeppAddr, plmnId)
			consumer.ExchangeProtectionPolicy(remoteSeppAddr, plmnId)
			consumer.ExchangeIPXInfo(remoteSeppAddr, plmnId)
		}
	}()
	return nil
	// switch n32fErrorInfo.N32fErrorType {
	// case models.N32fErrorType_CONTEXT_NOT_FOUND:

	// case models.N32fErrorType_DECIPHERING_FAILED:
	// 	//TODO
	// case models.N32fErrorType_ENCRYPTION_KEY_EXPIRED:

	// case models.N32fErrorType_INTEGRITY_CHECK_FAILED:

	// case models.N32fErrorType_INTEGRITY_CHECK_ON_MODIFICATIONS_FAILED:

	// case models.N32fErrorType_INTEGRITY_KEY_EXPIRED:

	// case models.N32fErrorType_MESSAGE_RECONSTRUCTION_FAILED:

	// case models.N32fErrorType_MODIFICATIONS_INSTRUCTIONS_FAILED:

	// case models.N32fErrorType_POLICY_MISMATCH:

	// }
}
