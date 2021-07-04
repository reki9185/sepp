package producer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"encoding/base64"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/free5gc/http_wrapper"
	"github.com/yangalan0903/openapi/models"
	"github.com/yangalan0903/sepp/consumer"
	sepp_context "github.com/yangalan0903/sepp/context"
	"github.com/yangalan0903/sepp/jose"
	"github.com/yangalan0903/sepp/jose/json"
	"github.com/yangalan0903/sepp/jsonhandler"
	"github.com/yangalan0903/sepp/logger"
	"golang.org/x/net/http2"
)

var (
	innerHTTP2Client = &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	innerHTTP2CleartextClient = &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		},
	}
)

type byteBuffer struct {
	data []byte
}

func HandleN32forwardMessage(request *http_wrapper.Request) *http_wrapper.Response {
	logger.N32fForward.Infof("handle N32forwardMessage")

	n32fReformattedReqMsg := request.Body.(models.N32fReformattedReqMsg)

	response, problemDetails := N32forwardMessageProcedure(n32fReformattedReqMsg)

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

func N32forwardMessageProcedure(n32fReformattedReqMsg models.N32fReformattedReqMsg) (*models.N32fReformattedRspMsg,
	*models.ProblemDetails) {

	var responseBody models.N32fReformattedRspMsg

	flatJweJson := n32fReformattedReqMsg.ReformattedData
	var rawJSONWebEncryption jose.RawJSONWebEncryption

	if data, err := base64.RawURLEncoding.DecodeString(flatJweJson.Protected); err != nil {
		logger.N32fForward.Errorln("flatJweJson.Protected decode error", err)
	} else {
		rawJSONWebEncryption.Protected = &jose.ByteBuffer{Data: data}
	}
	if data, err := base64.RawURLEncoding.DecodeString(flatJweJson.Aad); err != nil {
		logger.N32fForward.Errorln("flatJweJson.Aad decode error", err)
	} else {
		rawJSONWebEncryption.Aad = &jose.ByteBuffer{Data: data}
	}
	if data, err := base64.RawURLEncoding.DecodeString(flatJweJson.Ciphertext); err != nil {
		logger.N32fForward.Errorln("flatJweJson.Ciphertext decode error", err)
	} else {
		rawJSONWebEncryption.Ciphertext = &jose.ByteBuffer{Data: data}
	}
	if data, err := base64.RawURLEncoding.DecodeString(flatJweJson.EncryptedKey); err != nil {
		logger.N32fForward.Errorln("flatJweJson.EncryptedKey decode error", err)
	} else {
		rawJSONWebEncryption.EncryptedKey = &jose.ByteBuffer{Data: data}
	}
	if data, err := base64.RawURLEncoding.DecodeString(flatJweJson.Iv); err != nil {
		logger.N32fForward.Errorln("flatJweJson.Iv decode error", err)
	} else {
		rawJSONWebEncryption.Iv = &jose.ByteBuffer{Data: data}
	}
	if data, err := base64.RawURLEncoding.DecodeString(flatJweJson.Tag); err != nil {
		logger.N32fForward.Errorln("flatJweJson.Tag decode error", err)
	} else {
		rawJSONWebEncryption.Tag = &jose.ByteBuffer{Data: data}
	}
	var rawHeader jose.RawHeader
	for headerKey, rawMessage := range flatJweJson.Header {
		switch value := rawMessage.(type) {
		case nil:

		case *json.RawMessage:
			rawHeader[jose.HeaderKey(headerKey)] = value

		case []byte:
			rawHeader[jose.HeaderKey(headerKey)] = (*json.RawMessage)(&value)
		}
	}
	rawJSONWebEncryption.Header = &rawHeader
	rawHeader = jose.RawHeader{}
	for headerKey, rawMessage := range flatJweJson.Unprotected {
		switch value := rawMessage.(type) {
		case nil:

		case *json.RawMessage:
			rawHeader[jose.HeaderKey(headerKey)] = value

		case []byte:
			rawHeader[jose.HeaderKey(headerKey)] = (*json.RawMessage)(&value)
		}
	}
	rawJSONWebEncryption.Unprotected = &rawHeader

	jSONWebEncryption, err := rawJSONWebEncryption.Sanitized()
	if err != nil {
		logger.N32fForward.Errorln("generate jSONWebEncryption error", err)
	}
	decoded := jSONWebEncryption.GetAuthData()
	var dataToIntegrityProtectBlock models.DataToIntegrityProtectBlock
	var dataToIntegrityProtectAndCipherBlock models.DataToIntegrityProtectAndCipherBlock
	if err := json.Unmarshal(decoded, &dataToIntegrityProtectBlock); err != nil {
		logger.N32fForward.Errorln("144", err)
	}
	n32fContextId := dataToIntegrityProtectBlock.MetaData.N32fContextId
	self := sepp_context.GetSelf()
	n32fContext, ok := self.N32fContextPool[n32fContextId]
	if !ok {
		logger.N32fForward.Errorln("n32fContext not found")
		var problemDetails models.ProblemDetails
		problemDetails.Cause = "32fContext not found"
		problemDetails.Status = http.StatusBadRequest
		return nil, &problemDetails
	}
	recvReqKey := n32fContext.SecContext.SessionKeys.RecvReqKey
	decrypted, err := jSONWebEncryption.Decrypt(recvReqKey)
	if err != nil {
		logger.N32fForward.Errorln("JWE decrypt error", err)
		consumer.SendN32fErrorReport(n32fContext.PeerInformation.RemoteSeppAddress, models.N32fErrorInfo{
			N32fMessageId: dataToIntegrityProtectBlock.MetaData.MessageId,
			N32fErrorType: models.N32fErrorType_DECIPHERING_FAILED,
		})
		var problemDetails models.ProblemDetails
		problemDetails.Cause = "JWE decrypt error"
		problemDetails.Status = http.StatusBadRequest
		return nil, &problemDetails
	}
	if err := json.Unmarshal(decrypted, &dataToIntegrityProtectAndCipherBlock); err != nil {
		logger.N32fForward.Errorln("json unmarshal error", err)
	}
	if n32fReformattedReqMsg.ModificationsBlock != nil {
		object, payload := generaterawJSONWebSignature(n32fReformattedReqMsg.ModificationsBlock[0])
		var modifications models.Modifications
		if err := json.Unmarshal(payload, &modifications); err != nil {
			logger.Messageforward.Errorln("unmarshal error", err)
			var problemDetails models.ProblemDetails
			problemDetails.Cause = "unmarshal error"
			problemDetails.Status = http.StatusBadRequest
			return nil, &problemDetails
		}

		if problem := verifyJSONWebSignature(object, n32fContext.SecContext.IPXSecInfo, modifications.Identity); problem != nil {
			return nil, problem
		}
		var dataToIntegrityProtectBlockBeforePatch models.DataToIntegrityProtectBlock
		if dataToIntegrityProtectBlock, problem := verifyAndDoJsonPatch(dataToIntegrityProtectBlock, modifications); problem != nil {
			return nil, problem
		} else {
			dataToIntegrityProtectBlockBeforePatch = *dataToIntegrityProtectBlock
		}
		object, payload = generaterawJSONWebSignature(n32fReformattedReqMsg.ModificationsBlock[1])
		if err := json.Unmarshal(payload, &modifications); err != nil {
			logger.Messageforward.Errorln("unmarshal error", err)
			var problemDetails models.ProblemDetails
			problemDetails.Cause = "unmarshal error"
			problemDetails.Status = http.StatusBadRequest
			return nil, &problemDetails
		}

		if problem := verifyJSONWebSignature(object, self.SelfIPXSecInfo, modifications.Identity); problem != nil {
			return nil, problem
		}
		if dataToIntegrityProtectBlockBeforePatch, problem := verifyAndDoJsonPatch(dataToIntegrityProtectBlockBeforePatch, modifications); problem != nil {
			return nil, problem
		} else {
			dataToIntegrityProtectBlock = *dataToIntegrityProtectBlockBeforePatch
		}
	}
	reqBody := jsonhandler.BuildJsonBody(dataToIntegrityProtectBlock.Payload, dataToIntegrityProtectAndCipherBlock)

	newpath := string(dataToIntegrityProtectBlock.RequestLine.Scheme) + "://" + string(dataToIntegrityProtectBlock.RequestLine.Authority) + string(dataToIntegrityProtectBlock.RequestLine.Path)
	newUrl, err := url.Parse(newpath)
	if err != nil {
		logger.N32fForward.Errorln("parse path error", err)
	}
	newquery := newUrl.Query()
	var queryParam url.Values
	queryParam, _ = url.ParseQuery(dataToIntegrityProtectBlock.RequestLine.QueryFragment)
	for k, v := range queryParam {
		if v[0] == "encBlockIndex" {
			idx, err := strconv.Atoi(v[1])
			if err != nil {
				logger.Messageforward.Errorln("reformate message fail", err)
				var problemDetails models.ProblemDetails
				problemDetails.Cause = "reformate message fail"
				problemDetails.Status = http.StatusBadRequest
				return nil, &problemDetails
			}
			temp := dataToIntegrityProtectAndCipherBlock.DataToEncrypt[idx]["string"]
			newquery.Add(k, temp.(string))
		} else {
			for _, iv := range v {
				newquery.Add(k, iv)
			}
		}
	}

	newUrl.RawQuery = newquery.Encode()
	proxyReq, err := http.NewRequest(string(dataToIntegrityProtectBlock.RequestLine.Method), newUrl.String(), bytes.NewReader(reqBody))
	proxyReq.Header = make(http.Header)

	for _, header := range dataToIntegrityProtectBlock.Headers {
		if strings.HasPrefix(header.Value.Value, "encBlockIndex/") {
			if encBlockIndex, err := strconv.Atoi(header.Value.Value[14:]); err != nil {
				logger.N32fForward.Errorln("transfer encBlockIndex error", err)
			} else {
				proxyReq.Header[header.Header] = dataToIntegrityProtectAndCipherBlock.DataToEncrypt[encBlockIndex]["string"].([]string)
			}
		}
		proxyReq.Header.Add(header.Header, header.Value.Value)
	}
	var response http.Response
	var rspBody []byte
	switch string(dataToIntegrityProtectBlock.RequestLine.Scheme) {
	case "http":
		for {
			rsp, err := innerHTTP2CleartextClient.Do(proxyReq)
			if err != nil {
				logger.N32fForward.Errorln("send request to target NF failed")
				time.Sleep(2 * time.Second)
				continue
			} else {
				response = *rsp
				rspBody, err = ioutil.ReadAll(response.Body)
				rsp.Body.Close()
				if err != nil {
					logger.N32fForward.Errorln("rsp.Body.Close() error", err)
				}
				break
			}
		}
	case "https":
		for {
			rsp, err := innerHTTP2Client.Do(proxyReq)
			if err != nil {
				logger.N32fForward.Errorln("send request to target NF failed")
				time.Sleep(2 * time.Second)
				continue
			} else {
				response = *rsp
				rspBody, err = ioutil.ReadAll(response.Body)
				rsp.Body.Close()
				if err != nil {
					logger.N32fForward.Errorln("rsp.Body.Close() error", err)
				}
				break
			}
		}
	}

	// transfer NF's response for JWE
	var rspDataToIntegrityProtectBlock models.DataToIntegrityProtectBlock
	var rspDataToIntegrityProtectAndCipherBlock models.DataToIntegrityProtectAndCipherBlock

	rspDataToIntegrityProtectBlock.MetaData = &models.MetaData{
		N32fContextId:   n32fContext.N32fContextId,
		MessageId:       dataToIntegrityProtectBlock.MetaData.MessageId,
		AuthorizedIpxId: self.SelfIPXSecInfo[0].IpxProviderId,
	}
	temp := strconv.Itoa(response.StatusCode)

	rspDataToIntegrityProtectBlock.StatusLine = temp

	var headers []models.HttpHeader
	for k, headerValues := range response.Header {
		for _, value := range headerValues {
			data := models.EncodedHttpHeaderValue{
				Value: value,
			}
			header := models.HttpHeader{
				Header: k,
				Value:  &data,
			}
			headers = append(headers, header)
		}
	}

	if err != nil {
		logger.N32fForward.Errorf("read rspBody error")
	}

	payload := jsonhandler.ParseJsonBody(rspBody)

	var ieList []models.IeInfo
	for _, value := range n32fContext.SecContext.ProtectionPolicy.ApiIeMappingList {
		if value.ApiSignature.Uri == dataToIntegrityProtectBlock.RequestLine.Path && value.ApiMethod == dataToIntegrityProtectBlock.RequestLine.Method {
			ieList = value.IeList
			break
		}
	}
	jweKey := self.N32fContextPool[n32fContextId].SecContext.SessionKeys.RecvResKey
	seq := self.N32fContextPool[n32fContextId].SecContext.IVs.RecvReqSeq
	n32fContext.SecContext.IVs.RecvReqSeq = seq + 1
	self.N32fContextPool[n32fContextId] = n32fContext
	iv := self.N32fContextPool[n32fContextId].SecContext.IVs.RecvResIV
	if ieList == nil {
		problemDetail := models.ProblemDetails{
			Title:  "This api not support",
			Status: http.StatusForbidden,
			Cause:  "This api not support",
		}
		logger.Messageforward.Errorf("This api not support")
		return nil, &problemDetail
	}
	idx := 0
	dataTypeEncPolicy := self.LocalProtectionPolicy.DataTypeEncPolicy
	if n32fContext.SecContext.ProtectionPolicy.DataTypeEncPolicy != nil {
		dataTypeEncPolicy = n32fContext.SecContext.ProtectionPolicy.DataTypeEncPolicy
	}
	for _, ie := range ieList {
		needToEncrept := false
		for _, ieType := range dataTypeEncPolicy {
			if ie.IeType == ieType {
				needToEncrept = true
				break
			}
		}
		if needToEncrept {
			switch ie.IeLoc {
			case models.IeLocation_HEADER:
				for headerIdx, header := range headers {
					if header.Header == ie.RspIe {
						temp := make(map[string]interface{})
						temp["string"] = header.Value.Value
						rspDataToIntegrityProtectAndCipherBlock.DataToEncrypt = append(rspDataToIntegrityProtectAndCipherBlock.DataToEncrypt, temp)
						header.Value.Value = "encBlockIndex/" + string(idx)
						headers[headerIdx] = header
						idx++
					}
				}
			case models.IeLocation_BODY:
				for payloadIdx, value := range payload {
					if value.IePath == ie.RspIe {
						httpPayload := models.HttpPayload{
							IePath:          value.IePath,
							IeValueLocation: value.IeValueLocation,
							Value:           map[string]interface{}{"encBlockIndex": idx},
						}
						rspDataToIntegrityProtectAndCipherBlock.DataToEncrypt = append(rspDataToIntegrityProtectAndCipherBlock.DataToEncrypt, value.Value)
						payload[payloadIdx] = httpPayload
						idx++
					}
				}
			}
		}
	}
	rspDataToIntegrityProtectBlock.Headers = headers
	rspDataToIntegrityProtectBlock.Payload = payload

	var aad, clearText []byte
	if rawAad, err := json.Marshal(rspDataToIntegrityProtectBlock); err == nil {
		aad = rawAad
	}
	if rawClearText, err := json.Marshal(rspDataToIntegrityProtectAndCipherBlock); err == nil {
		clearText = rawClearText
	}

	var encrypter jose.Encrypter
	enc := self.N32fContextPool[n32fContextId].SecContext.CipherSuitList.JweCipherSuite
	switch enc {
	case "A128GCM":
		if temp, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.DIRECT, Key: jweKey, PBES2Count: int(seq), PBES2Salt: iv}, nil); err != nil {
			panic(err)
		} else {
			encrypter = temp
		}
	case "A256GCM":
		if temp, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.DIRECT, Key: jweKey, PBES2Count: int(seq), PBES2Salt: iv}, nil); err != nil {
			panic(err)
		} else {
			encrypter = temp
		}
	}

	object, err := encrypter.EncryptWithAuthData(clearText, aad)
	if err != nil {
		panic(err)
	}
	jweString := object.FullSerialize()
	jweStrings := strings.Split(jweString[1:len(jweString)-1], ",")
	var rspFlatJweJson models.FlatJweJson
	for _, value := range jweStrings {
		temp := strings.Split(value, ":")
		switch temp[0][1 : len(temp[0])-1] {
		case "protected":
			rspFlatJweJson.Protected = temp[1][1 : len(temp[1])-1]
		case "unprotected":
			// TODO
		case "header":
			// TODO
		case "encrypted_key":
			rspFlatJweJson.EncryptedKey = temp[1][1 : len(temp[1])-1]
		case "aad":
			rspFlatJweJson.Aad = temp[1][1 : len(temp[1])-1]
		case "ciphertext":
			rspFlatJweJson.Ciphertext = temp[1][1 : len(temp[1])-1]
		case "iv":
			rspFlatJweJson.Iv = temp[1][1 : len(temp[1])-1]
		case "tag":
			rspFlatJweJson.Tag = temp[1][1 : len(temp[1])-1]
		}
	}
	responseBody.ReformattedData = &rspFlatJweJson

	return &responseBody, nil

}

func BuildPublicKey(publicKeyStr string) (pubKey *ecdsa.PublicKey, e error) {
	bytes, e := base64.StdEncoding.DecodeString(publicKeyStr)
	if e != nil {
		return nil, e
	}
	split := strings.Split(string(bytes), "+")
	xStr := split[0]
	yStr := split[1]
	x := new(big.Int)
	y := new(big.Int)
	e = x.UnmarshalText([]byte(xStr))
	if e != nil {
		return nil, e
	}
	e = y.UnmarshalText([]byte(yStr))
	if e != nil {
		return nil, e
	}
	pub := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	pubKey = &pub
	return
}

func generaterawJSONWebSignature(flatJwsJson models.FlatJwsJson) (jose.JSONWebSignature, []byte) {
	var rawHeader jose.RawHeader
	var rawJSONWebSignature jose.RawJSONWebSignature
	for headerKey, rawMessage := range flatJwsJson.Header {
		switch value := rawMessage.(type) {
		case nil:

		case *json.RawMessage:
			rawHeader[jose.HeaderKey(headerKey)] = value

		case []byte:
			rawHeader[jose.HeaderKey(headerKey)] = (*json.RawMessage)(&value)
		}
	}
	rawJSONWebSignature.Header = &rawHeader
	payload, _ := base64.RawURLEncoding.DecodeString(flatJwsJson.Payload)
	rawJSONWebSignature.Payload = &jose.ByteBuffer{Data: payload}
	data, _ := base64.RawURLEncoding.DecodeString(flatJwsJson.Protected)
	rawJSONWebSignature.Protected = &jose.ByteBuffer{Data: data}
	data, _ = base64.RawURLEncoding.DecodeString(flatJwsJson.Signature)
	rawJSONWebSignature.Signature = &jose.ByteBuffer{Data: data}
	object, _ := rawJSONWebSignature.Sanitized()
	return *object, payload
}

func verifyJSONWebSignature(object jose.JSONWebSignature, iPXSecInfos []models.IpxProviderSecInfo, ipxId sepp_context.FQDN) *models.ProblemDetails {
	var iPXSecInfo *models.IpxProviderSecInfo
	for _, temp := range iPXSecInfos {
		if ipxId == temp.IpxProviderId {
			iPXSecInfo = &temp
			break
		}
	}
	if iPXSecInfo == nil {
		logger.Messageforward.Errorln("IPX not authorized")
		var problemDetails models.ProblemDetails
		problemDetails.Cause = "IPX not authorized"
		problemDetails.Status = http.StatusBadRequest
		return &problemDetails
	}
	var publicKey *ecdsa.PublicKey
	if temp, err := BuildPublicKey(iPXSecInfo.RawPublicKeyList[0]); err != nil {
		logger.Messageforward.Errorln("public error")
		var problemDetails models.ProblemDetails
		problemDetails.Cause = "public error"
		problemDetails.Status = http.StatusBadRequest
		return &problemDetails
	} else {
		publicKey = temp
	}
	if _, err := object.Verify(publicKey); err != nil {
		logger.Messageforward.Errorln("verify error")
		var problemDetails models.ProblemDetails
		problemDetails.Cause = "verify error"
		problemDetails.Status = http.StatusBadRequest
		return &problemDetails
	}
	return nil
}

func verifyAndDoJsonPatch(sourceJson models.DataToIntegrityProtectBlock, modifications models.Modifications) (*models.DataToIntegrityProtectBlock, *models.ProblemDetails) {
	for _, value := range modifications.Operations {
		temp := strings.Split(value.Path, "/")
		switch value.Op {
		case models.PatchOperation_ADD:
			switch temp[0] {
			case "header":
				idx, _ := strconv.Atoi(temp[1])
				headerMap := value.Value.(map[string]interface{})
				header := models.HttpHeader{
					Header: headerMap["header"].(string),
				}
				temp := headerMap["value"].(map[string]interface{})
				header.Value = &models.EncodedHttpHeaderValue{
					Value: temp["value"].(string),
				}
				sourceJson.Headers = append(sourceJson.Headers[:idx+1], sourceJson.Headers[idx:]...)
				sourceJson.Headers[idx] = header
			case "payload":
				idx, _ := strconv.Atoi(temp[1])
				payloadMap := value.Value.(map[string]interface{})
				payload := models.HttpPayload{
					IePath:          payloadMap["iePath"].(string),
					IeValueLocation: models.IeLocation(payloadMap["ieValueLocation"].(string)),
					Value:           payloadMap["value"].(map[string]interface{}),
				}
				sourceJson.Payload = append(sourceJson.Payload[:idx+1], sourceJson.Payload[idx:]...)
				sourceJson.Payload[idx] = payload

			case "URI_PARAM":
				queryParams, _ := url.ParseQuery(sourceJson.RequestLine.QueryFragment)
				queryParams.Add(temp[1], value.Value.(string))
				sourceJson.RequestLine.QueryFragment = queryParams.Encode()
			}
		case models.PatchOperation_COPY:
			switch temp[0] {
			case "header":
				idx, _ := strconv.Atoi(temp[1])
				idxFrom, _ := strconv.Atoi(strings.Split(value.From, "/")[1])
				sourceHeader := sourceJson.Headers[idxFrom]
				sourceJson.Headers = append(sourceJson.Headers[:idx+1], sourceJson.Headers[idx:]...)
				sourceJson.Headers[idx] = sourceHeader
			case "payload":
				idx, _ := strconv.Atoi(temp[1])
				idxFrom, _ := strconv.Atoi(strings.Split(value.From, "/")[1])
				sourcePayload := sourceJson.Payload[idxFrom]
				sourceJson.Payload = append(sourceJson.Payload[:idx+1], sourceJson.Payload[idx:]...)
				sourceJson.Payload[idx] = sourcePayload
			case "URI_PARAM":
				queryParams, _ := url.ParseQuery(sourceJson.RequestLine.QueryFragment)
				paramBody := queryParams.Get(strings.Split(value.From, "/")[1])
				queryParams.Add(temp[1], paramBody)
			}
		case models.PatchOperation_MOVE:
			switch temp[0] {
			case "header":
				idx, _ := strconv.Atoi(temp[1])
				idxFrom, _ := strconv.Atoi(strings.Split(value.From, "/")[1])
				sourceHeader := sourceJson.Headers[idxFrom]
				sourceJson.Headers = append(sourceJson.Headers[:idxFrom], sourceJson.Headers[idxFrom+1:]...)
				sourceJson.Headers = append(sourceJson.Headers[:idx+1], sourceJson.Headers[idx:]...)
				sourceJson.Headers[idx] = sourceHeader
			case "payload":
				idx, _ := strconv.Atoi(temp[1])
				idxFrom, _ := strconv.Atoi(strings.Split(value.From, "/")[1])
				sourcePayload := sourceJson.Payload[idxFrom]
				sourceJson.Payload = append(sourceJson.Payload[:idxFrom], sourceJson.Payload[idxFrom+1:]...)
				sourceJson.Payload = append(sourceJson.Payload[:idx+1], sourceJson.Payload[idx:]...)
				sourceJson.Payload[idx] = sourcePayload

			case "URI_PARAM":
			}
		case models.PatchOperation_REMOVE:
			switch temp[0] {
			case "header":
				idx, _ := strconv.Atoi(temp[1])
				sourceJson.Headers = append(sourceJson.Headers[:idx], sourceJson.Headers[idx+1:]...)
			case "payload":
				idx, _ := strconv.Atoi(temp[1])
				sourceJson.Payload = append(sourceJson.Payload[:idx], sourceJson.Payload[idx+1:]...)
			case "URI_PARAM":
				queryParams, _ := url.ParseQuery(sourceJson.RequestLine.QueryFragment)
				queryParams.Del(temp[1])
			}
		case models.PatchOperation_REPLACE:
			switch temp[0] {
			case "header":
				idx, _ := strconv.Atoi(temp[1])
				headerMap := value.Value.(map[string]interface{})
				header := models.HttpHeader{
					Header: headerMap["header"].(string),
				}
				temp := headerMap["value"].(map[string]interface{})
				header.Value = &models.EncodedHttpHeaderValue{
					Value: temp["value"].(string),
				}
				sourceJson.Headers[idx] = header
			case "payload":
				idx, _ := strconv.Atoi(temp[1])
				payloadMap := value.Value.(map[string]interface{})
				payload := models.HttpPayload{
					IePath:          payloadMap["iePath"].(string),
					IeValueLocation: models.IeLocation(payloadMap["ieValueLocation"].(string)),
					Value:           payloadMap["value"].(map[string]interface{}),
				}
				sourceJson.Payload[idx] = payload

			case "URI_PARAM":
				queryParams, _ := url.ParseQuery(sourceJson.RequestLine.QueryFragment)
				queryParams.Set(temp[1], value.Value.(string))
				sourceJson.RequestLine.QueryFragment = queryParams.Encode()
			}
		case models.PatchOperation_TEST:
			switch temp[0] {
			case "header":
				headerIdx, _ := strconv.Atoi(temp[1])
				headerMap := value.Value.(map[string]interface{})
				header := models.HttpHeader{
					Header: headerMap["header"].(string),
				}
				header.Value = &models.EncodedHttpHeaderValue{
					Value: headerMap["value"].(map[string]interface{})["value"].(string),
				}
				if !reflect.DeepEqual(sourceJson.Headers[headerIdx], header) {
					logger.Messageforward.Errorln("JSON patch test failed", header)
					var problemDetails models.ProblemDetails
					problemDetails.Cause = "JSON patch test failed"
					problemDetails.Status = http.StatusBadRequest
					return nil, &problemDetails
				}
			case "payload":
				idx, _ := strconv.Atoi(temp[1])
				payloadMap := value.Value.(map[string]interface{})
				payload := models.HttpPayload{
					IePath:          payloadMap["iePath"].(string),
					IeValueLocation: models.IeLocation(payloadMap["ieValueLocation"].(string)),
					Value:           payloadMap["value"].(map[string]interface{}),
				}
				if !reflect.DeepEqual(sourceJson.Payload[idx], payload) {
					logger.Messageforward.Errorln("JSON patch test failed", payload)
					var problemDetails models.ProblemDetails
					problemDetails.Cause = "JSON patch test failed"
					problemDetails.Status = http.StatusBadRequest
					return nil, &problemDetails
				}
			case "URI_PARAM":
				queryParams, _ := url.ParseQuery(sourceJson.RequestLine.QueryFragment)
				if !reflect.DeepEqual(value.Value.(string), queryParams.Get(temp[1])) {
					logger.Messageforward.Errorln("JSON patch test failed", value)
					var problemDetails models.ProblemDetails
					problemDetails.Cause = "JSON patch test failed"
					problemDetails.Status = http.StatusBadRequest
					return nil, &problemDetails
				}
			}
		}
	}
	return &sourceJson, nil
}
