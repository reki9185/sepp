package service

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/yangalan0903/sepp/jose/json"

	"github.com/free5gc/http_wrapper"
	"github.com/yangalan0903/openapi"
	"github.com/yangalan0903/openapi/models"
	"github.com/yangalan0903/sepp/consumer"
	sepp_context "github.com/yangalan0903/sepp/context"
	"github.com/yangalan0903/sepp/jose"
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

func HandleMessageForwarding(rspWriter http.ResponseWriter, request *http.Request) {
	logger.Messageforward.Infoln("forward message start")

	requestBody, err := ioutil.ReadAll(request.Body)
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		rspWriter.WriteHeader(http.StatusInternalServerError)
		rsp, err := json.Marshal(problemDetail)
		if err != nil {
			logger.Messageforward.Errorf("Encode problemDetail error: %+v", err)
		}
		rspWriter.Write(rsp)
		return
	}
	self := sepp_context.GetSelf()

	sbiTargetApiRoot := request.Header.Get("3gpp-Sbi-Target-apiRoot")
	if sbiTargetApiRoot == "" {
		problemDetail := models.ProblemDetails{
			Title:  "Header missing",
			Status: http.StatusBadRequest,
			Cause:  "SYSTEM_FAILURE",
		}
		logger.Messageforward.Errorf("3gpp-Sbi-Target-apiRoot header missing")
		rsp := http_wrapper.NewResponse(int(problemDetail.Status), nil, problemDetail)
		responseBody, _ := openapi.Serialize(rsp.Body, "application/json")
		rspWriter.WriteHeader(rsp.Status)
		rspWriter.Write(responseBody)
		return
	}
	temp := strings.Split(sbiTargetApiRoot, "://")
	uriScheme := temp[0]
	temp = strings.Split(temp[1], ":")
	plmnId := temp[0]
	targetAddrAndPort := temp[1] + ":" + temp[2]
	if self.SelfFqdn == plmnId {
		newUrl := uriScheme + "://" + targetAddrAndPort + request.RequestURI
		proxyReq, err := http.NewRequest(request.Method, newUrl, bytes.NewReader(requestBody))
		proxyReq.Header = make(http.Header)
		for h, val := range request.Header {
			proxyReq.Header[h] = val
		}

		var response http.Response
		var rspBody []byte
		switch string(uriScheme) {
		case "http":
			for {
				rsp, err := innerHTTP2CleartextClient.Do(proxyReq)
				if err != nil {
					logger.Messageforward.Errorln("send request to target NF failed")
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
					logger.Messageforward.Errorln("send request to target NF failed")
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

		for k, v := range response.Header {
			for _, vv := range v {
				rspWriter.Header().Add(k, vv)
			}
		}
		rspWriter.WriteHeader(response.StatusCode)
		_, err = rspWriter.Write(rspBody)
		if err != nil {
			logger.Messageforward.Errorf("rspwriter error:", err)
		}
		return
	} else {
		remoteSeppAddr, exist := self.FqdnIpMap[plmnId]
		if exist == false {
			problemDetail := models.ProblemDetails{
				Title:  "Target plmn not support",
				Status: http.StatusBadRequest,
				Cause:  "Target plmn not support",
			}
			logger.Messageforward.Errorf("Target plmn not support")
			rspWriter.WriteHeader(http.StatusBadRequest)
			rsp := http_wrapper.NewResponse(http.StatusBadRequest, nil, problemDetail)
			responseBody, _ := openapi.Serialize(rsp.Body, "application/json")
			rspWriter.Write(responseBody)
			return
		}
		secInfo, ok := self.PLMNSecInfo[plmnId]
		if !ok {
			logger.Messageforward.Infoln("Start handshake procedure:", plmnId)
			securityCapability, ok := consumer.SendExchangeCapability(remoteSeppAddr.IpForSBI)
			if !ok {
				problemDetail := models.ProblemDetails{
					Title:  "can't reach remote SEPP",
					Status: http.StatusForbidden,
					Cause:  "can't reach remote SEPP",
				}
				logger.Messageforward.Errorf("can't reach remote SEPP")
				rspWriter.WriteHeader(http.StatusForbidden)
				rsp, err := json.Marshal(problemDetail)
				if err != nil {
					logger.Messageforward.Errorf("Encode problemDetail error: %+v", err)
				}
				rspWriter.Write(rsp)
				return
			} else if *securityCapability == models.SecurityCapability_PRINS {
				consumer.ExchangeCiphersuite(remoteSeppAddr.IpForSBI, plmnId)
				consumer.ExchangeProtectionPolicy(remoteSeppAddr.IpForSBI, plmnId)
				consumer.ExchangeIPXInfo(remoteSeppAddr.IpForSBI, plmnId)
			}
		}
		if secInfo.SecCap == models.SecurityCapability_TLS {
			logger.Messageforward.Infoln("start tls forwarding procedure")
			if !secInfo.Var3GppSbiTargetApiRootSupported {
				logger.Messageforward.Infoln("3GppSbiTargetApiRoot not Supported")
				// TODO unsupport 3GppSbiTargetApiRoot
			} else {

				newUrl := remoteSeppAddr.IpForSBI + request.RequestURI
				proxyReq, err := http.NewRequest(request.Method, newUrl, bytes.NewReader(requestBody))
				proxyReq.Header = make(http.Header)
				for h, val := range request.Header {
					proxyReq.Header[h] = val
				}
				rsp, err := innerHTTP2Client.Do(proxyReq)
				if err != nil {
					http.Error(rspWriter, err.Error(), http.StatusBadGateway)
					return
				}
				defer rsp.Body.Close()

				for k, v := range rsp.Header {
					for _, vv := range v {
						rspWriter.Header().Add(k, vv)
					}
				}
				rspWriter.WriteHeader(rsp.StatusCode)
				result, err := ioutil.ReadAll(rsp.Body)
				if err != nil {
					logger.Messageforward.Errorf("read responseBody error:", err)
				}
				_, err = rspWriter.Write(result)
				if err != nil {
					logger.Messageforward.Errorf("rspWriter error:", err)
				}
			}
		} else if secInfo.SecCap == models.SecurityCapability_PRINS {
			var dataToIntegrityProtectBlock models.DataToIntegrityProtectBlock
			var dataToIntegrityProtectAndCipherBlock models.DataToIntegrityProtectAndCipherBlock
			n32fContext := self.N32fContextPool[secInfo.N32fContexId]
			var messageId string
			for {
				temp := fmt.Sprintf("%x", rand.Uint64())
				if _, ok := self.MessagePool.Load(temp); !ok {
					self.MessagePool.Store(temp, request)
					messageId = temp
					break
				}
			}
			metaData := models.MetaData{
				N32fContextId:   n32fContext.N32fContextId,
				MessageId:       messageId,
				AuthorizedIpxId: self.SelfIPXSecInfo[0].IpxProviderId,
			}
			requestLine := models.RequestLine{
				Method:          models.HttpMethod(request.Method),
				Scheme:          models.UriScheme(uriScheme),
				Authority:       targetAddrAndPort,
				Path:            request.URL.Path,
				ProtocolVersion: "2",
				QueryFragment:   request.URL.Query().Encode(),
			}

			var headers []models.HttpHeader
			for key, values := range request.Header {
				if key != "3gpp-Sbi-Target-Apiroot" {
					for _, value := range values {
						data := models.EncodedHttpHeaderValue{
							Value: value,
						}
						header := models.HttpHeader{
							Header: key,
							Value:  &data,
						}
						headers = append(headers, header)
					}
				}
			}
			payload := jsonhandler.ParseJsonBody(requestBody)

			var ieList []models.IeInfo

			for _, value := range self.LocalProtectionPolicy.ApiIeMappingList {
				if value.ApiSignature.Uri == request.URL.Path && value.ApiMethod == models.HttpMethod(request.Method) {
					ieList = value.IeList
					break
				}
			}
			jweKey := n32fContext.SecContext.SessionKeys.SendReqKey
			if ieList == nil {
				problemDetail := models.ProblemDetails{
					Title:  "This api not support",
					Status: http.StatusBadRequest,
					Cause:  "This api not support",
				}
				logger.Messageforward.Errorln("This api not support:", request.URL.Path)
				rspWriter.WriteHeader(http.StatusBadRequest)
				rsp, err := json.Marshal(problemDetail)
				if err != nil {
					logger.Messageforward.Errorf("Encode problemDetail error: %+v", err)
				}
				rspWriter.Write(rsp)
				self.MessagePool.Delete(messageId)
				return
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
							if header.Header == ie.ReqIe {
								temp := make(map[string]interface{})
								temp["string"] = header.Value.Value
								dataToIntegrityProtectAndCipherBlock.DataToEncrypt = append(dataToIntegrityProtectAndCipherBlock.DataToEncrypt, temp)
								header.Value.Value = "encBlockIndex/" + strconv.Itoa(idx)
								headers[headerIdx] = header
								idx++
							}
						}
					case models.IeLocation_BODY:
						for payloadIdx, value := range payload {
							if value.IePath == ie.ReqIe {
								httpPayload := models.HttpPayload{
									IePath:          value.IePath,
									IeValueLocation: value.IeValueLocation,
									Value:           map[string]interface{}{"encBlockIndex": idx},
								}
								dataToIntegrityProtectAndCipherBlock.DataToEncrypt = append(dataToIntegrityProtectAndCipherBlock.DataToEncrypt, value.Value)
								payload[payloadIdx] = httpPayload
								idx++
							}
						}
					case models.IeLocation_URI_PARAM:
						queryParams, _ := url.ParseQuery(requestLine.QueryFragment)
						if paramValue := queryParams.Get(ie.ReqIe); paramValue != "" {
							paramValue := queryParams[ie.ReqIe]
							dataToEncrypt := map[string]interface{}{
								"string": paramValue[0],
							}
							dataToIntegrityProtectAndCipherBlock.DataToEncrypt = append(dataToIntegrityProtectAndCipherBlock.DataToEncrypt, dataToEncrypt)
							queryParams[ie.ReqIe] = []string{"encBlockIndex", strconv.Itoa(idx)}
							requestLine.QueryFragment = queryParams.Encode()
							idx++
						}
					}
				}
				if ie.IsModifiable {
					switch ie.IeLoc {
					case models.IeLocation_HEADER:
						for headerIdx, header := range headers {
							if header.Header == ie.ReqIe {
								header.Value.Value = ""
								headers[headerIdx] = header
							}
						}
					case models.IeLocation_BODY:
						for payloadIdx, value := range payload {
							if value.IePath == ie.ReqIe {
								httpPayload := models.HttpPayload{
									IePath:          value.IePath,
									IeValueLocation: value.IeValueLocation,
									Value:           make(map[string]interface{}),
								}
								payload[payloadIdx] = httpPayload
							}
						}
					case models.IeLocation_URI_PARAM:
						queryParams, _ := url.ParseQuery(requestLine.QueryFragment)
						if paramValue := queryParams.Get(ie.ReqIe); paramValue != "" {
							queryParams[ie.ReqIe] = []string{""}
							requestLine.QueryFragment = queryParams.Encode()
						}
					}
				}
			}

			dataToIntegrityProtectBlock.Headers = headers
			dataToIntegrityProtectBlock.MetaData = &metaData
			dataToIntegrityProtectBlock.Payload = payload
			dataToIntegrityProtectBlock.RequestLine = &requestLine

			var aad, clearText []byte
			if rawAad, err := json.Marshal(dataToIntegrityProtectBlock); err == nil {
				aad = rawAad
			}
			if rawClearText, err := json.Marshal(dataToIntegrityProtectAndCipherBlock); err == nil {
				clearText = rawClearText
			}

			logger.Messageforward.Infoln("start send")

			// rsp, err := consumer.ForwardMessage(secInfo.N32fContexId, clearText, aad, remoteSeppAddr, jweKey)
			rsp, err := consumer.ForwardMessage(secInfo.N32fContexId, clearText, aad, self.IpxUri+"/"+n32fContext.PeerInformation.RemoteSeppAddress, jweKey)

			flatJweJson := rsp.ReformattedData
			var rawJSONWebEncryption jose.RawJSONWebEncryption
			if data, err := base64.RawURLEncoding.DecodeString(flatJweJson.Protected); err != nil {
				logger.Messageforward.Errorln("Decode flatJweJson.Protected error:", err)
			} else {
				rawJSONWebEncryption.Protected = &jose.ByteBuffer{Data: data}
			}
			if data, err := base64.RawURLEncoding.DecodeString(flatJweJson.Aad); err != nil {
				logger.Messageforward.Errorln("Decode flatJweJson.Aad error:", err)
			} else {
				rawJSONWebEncryption.Aad = &jose.ByteBuffer{Data: data}
			}
			if data, err := base64.RawURLEncoding.DecodeString(flatJweJson.Ciphertext); err != nil {
				logger.Messageforward.Errorln("Decode flatJweJson.Ciphertext error:", err)
			} else {
				rawJSONWebEncryption.Ciphertext = &jose.ByteBuffer{Data: data}
			}
			if data, err := base64.RawURLEncoding.DecodeString(flatJweJson.EncryptedKey); err != nil {
				logger.Messageforward.Errorln("Decode flatJweJson.EncryptedKey error:", err)
			} else {
				rawJSONWebEncryption.EncryptedKey = &jose.ByteBuffer{Data: data}
			}
			if data, err := base64.RawURLEncoding.DecodeString(flatJweJson.Iv); err != nil {
				logger.Messageforward.Errorln("Decode flatJweJson.Iv error:", err)
			} else {
				rawJSONWebEncryption.Iv = &jose.ByteBuffer{Data: data}
			}
			if data, err := base64.RawURLEncoding.DecodeString(flatJweJson.Tag); err != nil {
				logger.Messageforward.Errorln("Decode flatJweJson.Tag error:", err)
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
				logger.Messageforward.Errorln("generate jSONWebEncryption error:", err)
			}
			decoded := jSONWebEncryption.GetAuthData()

			var rspDataToIntegrityProtectBlock models.DataToIntegrityProtectBlock
			var rspDataToIntegrityProtectAndCipherBlock models.DataToIntegrityProtectAndCipherBlock

			if err := json.Unmarshal(decoded, &rspDataToIntegrityProtectBlock); err != nil {
				logger.N32fForward.Errorln(err)
			}

			n32fContextId := rspDataToIntegrityProtectBlock.MetaData.N32fContextId
			self := sepp_context.GetSelf()
			n32fContext, ok := self.N32fContextPool[n32fContextId]
			if !ok {
				logger.N32fForward.Errorf("n32fContext not found")
				var problemDetails models.ProblemDetails
				problemDetails.Cause = "32fContext not found"
				problemDetails.Status = http.StatusForbidden
				httpRsp := http_wrapper.NewResponse(http.StatusInternalServerError, nil, problemDetails)
				responseBody, err := openapi.Serialize(httpRsp.Body, "application/json")
				if err != nil {
					logger.N32fForward.Errorln(err)
					problemDetails := models.ProblemDetails{
						Status: http.StatusInternalServerError,
						Cause:  "SYSTEM_FAILURE",
						Detail: err.Error(),
					}
					rspWriter.WriteHeader(http.StatusInternalServerError)
					rsp, err := json.Marshal(problemDetails)
					if err != nil {
						logger.N32fForward.Errorf("Encode problemDetail error: %+v", err)
					}
					rspWriter.Write(rsp)
				} else {
					rspWriter.Header().Add("Content-Type", "application/json")
					rspWriter.Write(responseBody)
					self.MessagePool.Delete(messageId)
					return
				}
			}
			sendRspKey := n32fContext.SecContext.SessionKeys.SendResKey
			decrypted, err := jSONWebEncryption.Decrypt(sendRspKey)
			if err != nil {
				logger.Messageforward.Errorln("JWE decrypt error:", err)
			}
			if err := json.Unmarshal(decrypted, &rspDataToIntegrityProtectAndCipherBlock); err != nil {
				logger.Messageforward.Errorln("json unmarshal error:", err)
			}

			if rsp.ModificationsBlock != nil {
				object, payload := generaterawJSONWebSignature(rsp.ModificationsBlock[0])
				var modifications models.Modifications
				if err := json.Unmarshal(payload, &modifications); err != nil {
					logger.Messageforward.Errorln("unmarshall modification fail", err)
					var problemDetails models.ProblemDetails
					problemDetails.Cause = "unmarshall modification fail"
					problemDetails.Status = http.StatusInternalServerError
					rspWriter.WriteHeader(http.StatusInternalServerError)
					rsp, err := json.Marshal(problemDetails)
					if err != nil {
						logger.N32fForward.Errorf("Encode problemDetail error: %+v", err)
					}
					rspWriter.Write(rsp)
					self.MessagePool.Delete(messageId)
					return
				}

				if problem := verifyJSONWebSignature(object, n32fContext.SecContext.IPXSecInfo, modifications.Identity); problem != nil {
					rspWriter.WriteHeader(http.StatusInternalServerError)
					rsp, err := json.Marshal(problem)
					if err != nil {
						logger.N32fForward.Errorf("Encode problemDetail error: %+v", err)
					}
					rspWriter.Write(rsp)
					self.MessagePool.Delete(messageId)
					return
				}
				var dataToIntegrityProtectBlockBeforePatch models.DataToIntegrityProtectBlock
				var ieList []models.IeInfo
				for _, value := range n32fContext.SecContext.ProtectionPolicy.ApiIeMappingList {
					if value.ApiSignature.Uri == dataToIntegrityProtectBlock.RequestLine.Path && value.ApiMethod == dataToIntegrityProtectBlock.RequestLine.Method {
						ieList = value.IeList
						break
					}
				}
				if dataToIntegrityProtectBlock, problem := verifyAndDoJsonPatch(dataToIntegrityProtectBlock, modifications, ieList); problem != nil {
					rspWriter.WriteHeader(http.StatusInternalServerError)
					rsp, err := json.Marshal(problem)
					if err != nil {
						logger.N32fForward.Errorf("Encode problemDetail error: %+v", err)
					}
					rspWriter.Write(rsp)
					self.MessagePool.Delete(messageId)
					return
				} else {
					dataToIntegrityProtectBlockBeforePatch = *dataToIntegrityProtectBlock
				}
				object, payload = generaterawJSONWebSignature(rsp.ModificationsBlock[1])
				if err := json.Unmarshal(payload, &modifications); err != nil {
					logger.Messageforward.Errorln("unmarshall modification fail", err)
					var problemDetails models.ProblemDetails
					problemDetails.Cause = "unmarshall modification fail"
					problemDetails.Status = http.StatusInternalServerError
					rspWriter.WriteHeader(http.StatusInternalServerError)
					rsp, err := json.Marshal(problemDetails)
					if err != nil {
						logger.N32fForward.Errorf("Encode problemDetail error: %+v", err)
					}
					rspWriter.Write(rsp)
					self.MessagePool.Delete(messageId)
					return
				}

				if problem := verifyJSONWebSignature(object, self.SelfIPXSecInfo, modifications.Identity); problem != nil {
					rspWriter.WriteHeader(http.StatusInternalServerError)
					rsp, err := json.Marshal(problem)
					if err != nil {
						logger.N32fForward.Errorf("Encode problemDetail error: %+v", err)
					}
					rspWriter.Write(rsp)
					self.MessagePool.Delete(messageId)
					return
				}
				if dataToIntegrityProtectBlockBeforePatch, problem := verifyAndDoJsonPatch(dataToIntegrityProtectBlockBeforePatch, modifications, ieList); problem != nil {
					rspWriter.WriteHeader(http.StatusInternalServerError)
					rsp, err := json.Marshal(problem)
					if err != nil {
						logger.N32fForward.Errorf("Encode problemDetail error: %+v", err)
					}
					rspWriter.Write(rsp)
					self.MessagePool.Delete(messageId)
					return
				} else {
					dataToIntegrityProtectBlock = *dataToIntegrityProtectBlockBeforePatch
				}
			}

			rspBody := jsonhandler.BuildJsonBody(rspDataToIntegrityProtectBlock.Payload, rspDataToIntegrityProtectAndCipherBlock)

			for _, header := range rspDataToIntegrityProtectBlock.Headers {
				if strings.HasPrefix(header.Value.Value, "encBlockIndex") {
					encBlockIndex, _ := strconv.Atoi(header.Value.Value[14:])
					for _, value := range rspDataToIntegrityProtectAndCipherBlock.DataToEncrypt[encBlockIndex] {
						rspWriter.Header().Add(header.Header, value.(string))
					}
				}
				rspWriter.Header().Add(header.Header, header.Value.Value)
			}

			rspWriter.Header().Add("Content-Type", "application/json")
			temp, _ := strconv.Atoi(rspDataToIntegrityProtectBlock.StatusLine)
			rspWriter.WriteHeader(temp)

			rspWriter.Write(rspBody)
			self.MessagePool.Delete(messageId)
			return
		}
	}
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

func verifyAndDoJsonPatch(sourceJson models.DataToIntegrityProtectBlock, modifications models.Modifications, ieList []models.IeInfo) (*models.DataToIntegrityProtectBlock, *models.ProblemDetails) {
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
				if problem := VerifyIPXOperationForHeader(ieList, header); problem != nil {
					return nil, problem
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
				if problem := VerifyIPXOperationForPayload(ieList, payload); problem != nil {
					return nil, problem
				}
				sourceJson.Payload = append(sourceJson.Payload[:idx+1], sourceJson.Payload[idx:]...)
				sourceJson.Payload[idx] = payload

			case "URI_PARAM":
				queryParams, _ := url.ParseQuery(sourceJson.RequestLine.QueryFragment)
				if problem := VerifyIPXOperationForQuery(ieList, temp[1]); problem != nil {
					return nil, problem
				}
				queryParams.Add(temp[1], value.Value.(string))
				sourceJson.RequestLine.QueryFragment = queryParams.Encode()
			}
		case models.PatchOperation_COPY:
			switch temp[0] {
			case "header":
				idx, _ := strconv.Atoi(temp[1])
				idxFrom, _ := strconv.Atoi(strings.Split(value.From, "/")[1])
				sourceHeader := sourceJson.Headers[idxFrom]
				if problem := VerifyIPXOperationForHeader(ieList, sourceHeader); problem != nil {
					return nil, problem
				}
				sourceJson.Headers = append(sourceJson.Headers[:idx+1], sourceJson.Headers[idx:]...)
				sourceJson.Headers[idx] = sourceHeader
			case "payload":
				idx, _ := strconv.Atoi(temp[1])
				idxFrom, _ := strconv.Atoi(strings.Split(value.From, "/")[1])
				sourcePayload := sourceJson.Payload[idxFrom]
				if problem := VerifyIPXOperationForPayload(ieList, sourcePayload); problem != nil {
					return nil, problem
				}
				sourceJson.Payload = append(sourceJson.Payload[:idx+1], sourceJson.Payload[idx:]...)
				sourceJson.Payload[idx] = sourcePayload
			case "URI_PARAM":
				queryParams, _ := url.ParseQuery(sourceJson.RequestLine.QueryFragment)
				paramBody := queryParams.Get(strings.Split(value.From, "/")[1])
				if problem := VerifyIPXOperationForQuery(ieList, temp[1]); problem != nil {
					return nil, problem
				}
				queryParams.Add(temp[1], paramBody)
			}
		case models.PatchOperation_MOVE:
			switch temp[0] {
			case "header":
				idx, _ := strconv.Atoi(temp[1])
				idxFrom, _ := strconv.Atoi(strings.Split(value.From, "/")[1])
				sourceHeader := sourceJson.Headers[idxFrom]
				if problem := VerifyIPXOperationForHeader(ieList, sourceHeader); problem != nil {
					return nil, problem
				}
				sourceJson.Headers = append(sourceJson.Headers[:idxFrom], sourceJson.Headers[idxFrom+1:]...)
				sourceJson.Headers = append(sourceJson.Headers[:idx+1], sourceJson.Headers[idx:]...)
				sourceJson.Headers[idx] = sourceHeader
			case "payload":
				idx, _ := strconv.Atoi(temp[1])
				idxFrom, _ := strconv.Atoi(strings.Split(value.From, "/")[1])
				sourcePayload := sourceJson.Payload[idxFrom]
				if problem := VerifyIPXOperationForPayload(ieList, sourcePayload); problem != nil {
					return nil, problem
				}
				sourceJson.Payload = append(sourceJson.Payload[:idxFrom], sourceJson.Payload[idxFrom+1:]...)
				sourceJson.Payload = append(sourceJson.Payload[:idx+1], sourceJson.Payload[idx:]...)
				sourceJson.Payload[idx] = sourcePayload
			}
		case models.PatchOperation_REMOVE:
			switch temp[0] {
			case "header":
				idx, _ := strconv.Atoi(temp[1])
				if problem := VerifyIPXOperationForHeader(ieList, sourceJson.Headers[idx]); problem != nil {
					return nil, problem
				}
				sourceJson.Headers = append(sourceJson.Headers[:idx], sourceJson.Headers[idx+1:]...)
			case "payload":
				idx, _ := strconv.Atoi(temp[1])
				if problem := VerifyIPXOperationForPayload(ieList, sourceJson.Payload[idx]); problem != nil {
					return nil, problem
				}
				sourceJson.Payload = append(sourceJson.Payload[:idx], sourceJson.Payload[idx+1:]...)
			case "URI_PARAM":
				queryParams, _ := url.ParseQuery(sourceJson.RequestLine.QueryFragment)
				if problem := VerifyIPXOperationForQuery(ieList, temp[1]); problem != nil {
					return nil, problem
				}
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
				if problem := VerifyIPXOperationForHeader(ieList, header); problem != nil {
					return nil, problem
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
				if problem := VerifyIPXOperationForPayload(ieList, payload); problem != nil {
					return nil, problem
				}
				sourceJson.Payload[idx] = payload
			case "URI_PARAM":
				queryParams, _ := url.ParseQuery(sourceJson.RequestLine.QueryFragment)
				if problem := VerifyIPXOperationForQuery(ieList, temp[1]); problem != nil {
					return nil, problem
				}
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
				if problem := VerifyIPXOperationForHeader(ieList, header); problem != nil {
					return nil, problem
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
				if problem := VerifyIPXOperationForPayload(ieList, payload); problem != nil {
					return nil, problem
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
				if problem := VerifyIPXOperationForQuery(ieList, temp[1]); problem != nil {
					return nil, problem
				}
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

func VerifyIPXOperationForHeader(ieList []models.IeInfo, header models.HttpHeader) *models.ProblemDetails {
	for _, ie := range ieList {
		if ie.IeLoc == models.IeLocation_HEADER && ie.RspIe == header.Header {
			if ie.IsModifiable {
				return nil
			} else {
				break
			}
		}
	}
	logger.Messageforward.Errorln("IPX's op not authorizes", header)
	var problemDetails models.ProblemDetails
	problemDetails.Cause = "IPX's op not authorizes"
	problemDetails.Status = http.StatusInternalServerError
	return &problemDetails
}

func VerifyIPXOperationForPayload(ieList []models.IeInfo, payload models.HttpPayload) *models.ProblemDetails {
	for _, ie := range ieList {
		if ie.IeLoc == models.IeLocation_BODY && ie.RspIe == payload.IePath {
			if ie.IsModifiable {
				return nil
			} else {
				break
			}
		}
	}
	logger.Messageforward.Errorln("IPX's op not authorizes", payload)
	var problemDetails models.ProblemDetails
	problemDetails.Cause = "IPX's op not authorizes"
	problemDetails.Status = http.StatusInternalServerError
	return &problemDetails
}

func VerifyIPXOperationForQuery(ieList []models.IeInfo, queryParam string) *models.ProblemDetails {
	for _, ie := range ieList {
		if ie.IeLoc == models.IeLocation_URI_PARAM && ie.RspIe == queryParam {
			if ie.IsModifiable {
				return nil
			} else {
				break
			}
		}
	}
	logger.Messageforward.Errorln("IPX's op not authorizes", queryParam)
	var problemDetails models.ProblemDetails
	problemDetails.Cause = "IPX's op not authorizes"
	problemDetails.Status = http.StatusInternalServerError
	return &problemDetails
}
