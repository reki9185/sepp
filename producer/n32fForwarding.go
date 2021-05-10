package producer

import (
	// "context"
	// "crypto/sha256"
	// "encoding/base64"
	// "encoding/hex"
	// "fmt"
	// "math/rand"

	"encoding/base64"
	"fmt"
	"net/http"

	// "time"

	// "github.com/bronze1man/radius"
	// "github.com/google/gopacket"
	// "github.com/google/gopacket/layers"

	// "github.com/free5gc/UeauCommon"

	"github.com/free5gc/http_wrapper"
	"github.com/yangalan0903/openapi/models"
	sepp_context "github.com/yangalan0903/sepp/context"
	"github.com/yangalan0903/sepp/logger"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/json"
)

type byteBuffer struct {
	data []byte
}

func HandleN32forwardMessage(request *http_wrapper.Request) *http_wrapper.Response {
	logger.N32fForward.Infof("handle PostN32fTerminate")

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
		fmt.Println(err)
	} else {
		rawJSONWebEncryption.Protected = &jose.ByteBuffer{Data: data}
	}
	if data, err := base64.RawURLEncoding.DecodeString(flatJweJson.Aad); err != nil {
		fmt.Println(err)
	} else {
		rawJSONWebEncryption.Aad = &jose.ByteBuffer{Data: data}
	}
	if data, err := base64.RawURLEncoding.DecodeString(flatJweJson.Ciphertext); err != nil {
		fmt.Println(err)
	} else {
		rawJSONWebEncryption.Ciphertext = &jose.ByteBuffer{Data: data}
	}
	if data, err := base64.RawURLEncoding.DecodeString(flatJweJson.EncryptedKey); err != nil {
		fmt.Println(err)
	} else {
		rawJSONWebEncryption.EncryptedKey = &jose.ByteBuffer{Data: data}
	}
	if data, err := base64.RawURLEncoding.DecodeString(flatJweJson.Iv); err != nil {
		fmt.Println(err)
	} else {
		rawJSONWebEncryption.Iv = &jose.ByteBuffer{Data: data}
	}
	if data, err := base64.RawURLEncoding.DecodeString(flatJweJson.Tag); err != nil {
		fmt.Println(err)
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

	jSONWebEncryption, erro := rawJSONWebEncryption.Sanitized()
	if erro != nil {
		fmt.Println("error:", erro)
	}
	decoded := jSONWebEncryption.GetAuthData()
	var dataToIntegrityProtectBlock models.DataToIntegrityProtectBlock
	if err := json.Unmarshal(decoded, &dataToIntegrityProtectBlock); err != nil {
		fmt.Println("error:", err)
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
		fmt.Println(err)
	}
	fmt.Println(string(decrypted))
	// var dataToIntegrityProtectAndCipherBlock models.DataToIntegrityProtectAndCipherBlock
	// if err := json.Unmarshal(decrypted, &dataToIntegrityProtectAndCipherBlock); err != nil {
	// 	fmt.Println("error:", err)
	// }
	// switch dataToIntegrityProtectBlock.RequestLine.Path {
	// case "nnrf-disc":
	// 	// var targetNfType, requestNfType models.NfType
	// 	for _, ie := range dataToIntegrityProtectBlock.Payload {
	// 		ieLocation := strings.Split(ie.IePath, "/")
	// 		switch ieLocation[0] {
	// 		case "targetNfType":

	// 		}
	// 	}
	// }

	return &responseBody, nil

}
