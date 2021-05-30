package service

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
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
		// ctx.JSON(http.StatusInternalServerError, problemDetail)
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
		rspWriter.WriteHeader(http.StatusBadRequest)
		rsp, err := json.Marshal(problemDetail)
		if err != nil {
			logger.Messageforward.Errorf("Encode problemDetail error: %+v", err)
		}
		rspWriter.Write(rsp)
		// ctx.JSON(http.StatusInternalServerError, problemDetail)
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
			rsp, err := json.Marshal(problemDetail)
			if err != nil {
				logger.Messageforward.Errorf("Encode problemDetail error: %+v", err)
			}
			rspWriter.Write(rsp)
			// ctx.JSON(http.StatusInternalServerError, problemDetail)
			return
		}
		secInfo, _ := self.PLMNSecInfo[plmnId]
		if secInfo.SecCap == models.SecurityCapability_TLS {
			logger.Messageforward.Infoln("start tls forwarding procedure")

			newUrl := remoteSeppAddr + request.RequestURI
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
		} else if secInfo.SecCap == models.SecurityCapability_PRINS {
			var dataToIntegrityProtectBlock models.DataToIntegrityProtectBlock
			var dataToIntegrityProtectAndCipherBlock models.DataToIntegrityProtectAndCipherBlock
			messageId := fmt.Sprintf("%x", rand.Uint64())
			metaData := models.MetaData{
				N32fContextId:   self.N32fContextPool[secInfo.N32fContexId].N32fContextId,
				MessageId:       messageId,
				AuthorizedIpxId: "NULL",
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

			for _, value := range self.N32fContextPool[secInfo.N32fContexId].SecContext.ProtectionPolicy.ApiIeMappingList {
				if value.ApiSignature.Uri == request.URL.Path && value.ApiMethod == models.HttpMethod(request.Method) {
					ieList = value.IeList
					break
				}
			}
			jweKey := self.N32fContextPool[secInfo.N32fContexId].SecContext.SessionKeys.SendReqKey
			if ieList == nil {
				problemDetail := models.ProblemDetails{
					Title:  "This api not support",
					Status: http.StatusBadRequest,
					Cause:  "This api not support",
				}
				logger.Messageforward.Errorf("This api not support")
				rspWriter.WriteHeader(http.StatusBadRequest)
				rsp, err := json.Marshal(problemDetail)
				if err != nil {
					logger.Messageforward.Errorf("Encode problemDetail error: %+v", err)
				}
				rspWriter.Write(rsp)
				return
			}
			idx := 0
			for _, ie := range ieList {
				switch ie.IeLoc {
				case models.IeLocation_HEADER:
					for headerIdx, header := range headers {
						if header.Header == ie.ReqIe {
							temp := make(map[string]interface{})
							temp["string"] = header.Value.Value
							dataToIntegrityProtectAndCipherBlock.DataToEncrypt = append(dataToIntegrityProtectAndCipherBlock.DataToEncrypt, temp)
							header.Value.Value = "encBlockIndex/" + string(idx)
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
						queryParams[ie.ReqIe] = []string{"encBlockIndex", string(idx)}
						requestLine.QueryFragment = queryParams.Encode()
						idx++
					}
				}
			}

			dataToIntegrityProtectBlock.Headers = headers
			dataToIntegrityProtectBlock.MetaData = &metaData
			dataToIntegrityProtectBlock.Payload = payload
			dataToIntegrityProtectBlock.RequestLine = &requestLine

			var aad, clearText []byte
			if rawAad, err := json.Marshal(dataToIntegrityProtectBlock); err == nil {
				buf := make([]byte, base64.RawURLEncoding.EncodedLen(len(rawAad)))
				base64.RawURLEncoding.Encode(buf, rawAad)
				aad = buf
			}
			if rawClearText, err := json.Marshal(dataToIntegrityProtectAndCipherBlock); err == nil {
				buf := make([]byte, base64.RawURLEncoding.EncodedLen(len(rawClearText)))
				base64.RawURLEncoding.Encode(buf, rawClearText)
				clearText = buf
			}

			logger.Messageforward.Infoln("start send")
			rsp, err := consumer.ForwardMessage(secInfo.N32fContexId, clearText, aad, remoteSeppAddr, jweKey)

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

			buf := make([]byte, base64.RawURLEncoding.DecodedLen(len(decoded)))
			n, err := base64.RawURLEncoding.Decode(buf, decoded)

			if err := json.Unmarshal(buf[:n], &rspDataToIntegrityProtectBlock); err != nil {
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
				// TODO return error
				httpRsp := http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
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
					// ctx.JSON(http.StatusInternalServerError, problemDetails)
				} else {
					rspWriter.Header().Add("Content-Type", "application/json")
					rspWriter.Write(responseBody)
					// ctx.Data(rsp.Status, "application/json", responseBody)
				}
			}
			sendRspKey := n32fContext.SecContext.SessionKeys.SendResKey
			decrypted, err := jSONWebEncryption.Decrypt(sendRspKey)
			if err != nil {
				logger.Messageforward.Errorln("JWE decrypt error:", err)
			}

			n, err = base64.RawURLEncoding.Decode(buf, decrypted)
			if err != nil {
				logger.Messageforward.Errorln("base64URL data decode error:", err)
			}
			if err := json.Unmarshal(buf[:n], &rspDataToIntegrityProtectAndCipherBlock); err != nil {
				logger.Messageforward.Errorln("json unmarshal error:", err)
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
			return
		}
	}
}
