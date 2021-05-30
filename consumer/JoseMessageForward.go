package consumer

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"encoding/json"

	"github.com/yangalan0903/openapi/JOSEProtectedMessageForwarding"
	"github.com/yangalan0903/openapi/models"
	sepp_context "github.com/yangalan0903/sepp/context"
	"github.com/yangalan0903/sepp/jose"
)

func ForwardMessage(n32fContextId string, plainText, aad []byte, seppUri string, key []byte) (models.N32fReformattedRspMsg, error) {
	configuration := JOSEProtectedMessageForwarding.NewConfiguration()
	configuration.SetBasePath(seppUri)
	client := JOSEProtectedMessageForwarding.NewAPIClient(configuration)

	var n32fReformattedReqMsg models.N32fReformattedReqMsg

	self := sepp_context.GetSelf()
	var encrypter jose.Encrypter
	enc := self.N32fContextPool[n32fContextId].SecContext.CipherSuitList.JweCipherSuite
	switch enc {
	case "A128GCM":
		if temp, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.DIRECT, Key: key}, nil); err != nil {
			panic(err)
		} else {
			encrypter = temp
		}
	case "A256GCM":
		if temp, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.DIRECT, Key: key}, nil); err != nil {
			panic(err)
		} else {
			encrypter = temp
		}
	}

	object, err := encrypter.EncryptWithAuthData(plainText, aad)
	if err != nil {
		panic(err)
	}
	jweString := object.FullSerialize()
	object, _ = jose.ParseEncrypted(jweString)
	var flatJweJson models.FlatJweJson
	rawJSONWebEncryption := object.Original
	if rawJSONWebEncryption.Aad != nil {
		if data, err := rawJSONWebEncryption.Aad.MarshalJSON(); err == nil {
			if err := json.Unmarshal(data, &flatJweJson.Aad); err != nil {
				fmt.Println(err)
			}
		}
	}
	if rawJSONWebEncryption.Ciphertext != nil {
		if data, err := rawJSONWebEncryption.Ciphertext.MarshalJSON(); err == nil {
			if err := json.Unmarshal(data, &flatJweJson.Ciphertext); err != nil {
				fmt.Println(err)
			}
		}
	}
	if rawJSONWebEncryption.Protected != nil {
		if data, err := rawJSONWebEncryption.Protected.MarshalJSON(); err == nil {
			if err := json.Unmarshal(data, &flatJweJson.Protected); err != nil {
				fmt.Println(err)
			}
		}
	}
	if rawJSONWebEncryption.EncryptedKey != nil {
		if data, err := rawJSONWebEncryption.EncryptedKey.MarshalJSON(); err == nil {
			if err := json.Unmarshal(data, &flatJweJson.EncryptedKey); err != nil {
				fmt.Println(err)
			}
		}
	}
	if rawJSONWebEncryption.Iv != nil {
		if data, err := rawJSONWebEncryption.Iv.MarshalJSON(); err == nil {
			if err := json.Unmarshal(data, &flatJweJson.Iv); err != nil {
				fmt.Println(err)
			}
		}
	}
	if rawJSONWebEncryption.Tag != nil {
		if data, err := rawJSONWebEncryption.Tag.MarshalJSON(); err == nil {
			if err := json.Unmarshal(data, &flatJweJson.Tag); err != nil {
				fmt.Println(err)
			}
		}
	}
	if rawJSONWebEncryption.Header != nil {
		for headerKey, rawMessage := range *rawJSONWebEncryption.Header {
			flatJweJson.Header[string(headerKey)] = rawMessage
		}
	}
	if rawJSONWebEncryption.Unprotected != nil {
		for headerKey, rawMessage := range *rawJSONWebEncryption.Unprotected {
			flatJweJson.Unprotected[string(headerKey)] = rawMessage
		}
	}

	n32fReformattedReqMsg.ReformattedData = &flatJweJson

	var res *http.Response
	for {
		rsp, resTmp, err := client.N32FForwardApi.PostN32fProcess(context.TODO(), n32fReformattedReqMsg, nil)
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
			return rsp, err
		} else {
			fmt.Println(fmt.Errorf("handler returned wrong status code %d", status))
			fmt.Println(fmt.Errorf("remote sepp return wrong status code %d", status))
		}
	}
}
