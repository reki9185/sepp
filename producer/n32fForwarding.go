package producer

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/free5gc/http_wrapper"
	"github.com/yangalan0903/openapi/models"
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
		logger.N32fForward.Errorln(err)
	}
	n32fContextId := dataToIntegrityProtectBlock.MetaData.N32fContextId
	self := sepp_context.GetSelf()
	n32fContext, ok := self.N32fContextPool[n32fContextId]
	if !ok {
		logger.N32fForward.Infof("n32fContext not found")
		var problemDetails models.ProblemDetails
		problemDetails.Cause = "32fContext not found"
		problemDetails.Status = http.StatusBadRequest
		// TODO return error
		return nil, &problemDetails
	}
	recvReqKey := n32fContext.SecContext.SessionKeys.RecvReqKey
	decrypted, err := jSONWebEncryption.Decrypt(recvReqKey)
	if err != nil {
		logger.N32fForward.Errorln("JWE decrypt error", err)
	}
	if err := json.Unmarshal(decrypted, &dataToIntegrityProtectAndCipherBlock); err != nil {
		logger.N32fForward.Errorln("json unmarshal error", err)
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
		for _, iv := range v {
			newquery.Add(k, iv)
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
		N32fContextId:   n32fContextId,
		MessageId:       dataToIntegrityProtectBlock.MetaData.MessageId,
		AuthorizedIpxId: "NULL",
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
	for _, value := range self.LocalProtectionPolicy.ApiIeMappingList {
		if value.ApiSignature.Uri == dataToIntegrityProtectBlock.RequestLine.Path && value.ApiMethod == dataToIntegrityProtectBlock.RequestLine.Method {
			ieList = value.IeList
			break
		}
	}
	fmt.Println(dataToIntegrityProtectBlock.RequestLine.Path)
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
	for _, ie := range ieList {
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
	object, _ = jose.ParseEncrypted(jweString)
	var rspFlatJweJson models.FlatJweJson
	rspRawJSONWebEncryption := object.Original
	if rspRawJSONWebEncryption.Aad != nil {
		if data, err := rspRawJSONWebEncryption.Aad.MarshalJSON(); err == nil {
			if err := json.Unmarshal(data, &rspFlatJweJson.Aad); err != nil {
				logger.N32fForward.Errorln("json unmarshal error", err)
			}
		}
	}
	if rspRawJSONWebEncryption.Ciphertext != nil {
		if data, err := rspRawJSONWebEncryption.Ciphertext.MarshalJSON(); err == nil {
			if err := json.Unmarshal(data, &rspFlatJweJson.Ciphertext); err != nil {
				logger.N32fForward.Errorln("json unmarshal error", err)
			}
		}
	}
	if rspRawJSONWebEncryption.Protected != nil {
		if data, err := rspRawJSONWebEncryption.Protected.MarshalJSON(); err == nil {
			if err := json.Unmarshal(data, &rspFlatJweJson.Protected); err != nil {
				logger.N32fForward.Errorln("json unmarshal error", err)
			}
		}
	}
	if rspRawJSONWebEncryption.EncryptedKey != nil {
		if data, err := rspRawJSONWebEncryption.EncryptedKey.MarshalJSON(); err == nil {
			if err := json.Unmarshal(data, &rspFlatJweJson.EncryptedKey); err != nil {
				logger.N32fForward.Errorln("json unmarshal error", err)
			}
		}
	}
	if rspRawJSONWebEncryption.Iv != nil {
		if data, err := rspRawJSONWebEncryption.Iv.MarshalJSON(); err == nil {
			if err := json.Unmarshal(data, &rspFlatJweJson.Iv); err != nil {
				logger.N32fForward.Errorln("json unmarshal error", err)
				fmt.Println(err)
			}
			if data, err := rspRawJSONWebEncryption.Tag.MarshalJSON(); err == nil {
				if err := json.Unmarshal(data, &rspFlatJweJson.Tag); err != nil {
					logger.N32fForward.Errorln("json unmarshal error", err)
				}
			}
		}
		if rspRawJSONWebEncryption.Header != nil {
			for headerKey, rawMessage := range *rspRawJSONWebEncryption.Header {
				rspFlatJweJson.Header[string(headerKey)] = rawMessage
			}
		}
		if rspRawJSONWebEncryption.Unprotected != nil {
			for headerKey, rawMessage := range *rspRawJSONWebEncryption.Unprotected {
				rspFlatJweJson.Unprotected[string(headerKey)] = rawMessage
			}
		}
	}
	responseBody.ReformattedData = &rspFlatJweJson

	return &responseBody, nil

}
