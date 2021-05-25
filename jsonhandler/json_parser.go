package jsonhandler

import (
	"encoding/json"
	"fmt"

	"github.com/buger/jsonparser"
	"github.com/yangalan0903/openapi/models"
)

func ParseJsonBody(jsondata []byte) []models.HttpPayload {
	var httpPayload []models.HttpPayload
	var iterateKey []string

	var objHandler func([]byte, []byte, jsonparser.ValueType, int) error

	objHandler = func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
		if dataType == 3 {
			iterateKey = append(iterateKey, string(key))
			jsonparser.ObjectEach(jsondata, objHandler, iterateKey...)
		} else if dataType == 4 {
			iterateKey = append(iterateKey, string(key))
			lenOfArray := 0
			for true {
				iterateKey = append(iterateKey, "["+fmt.Sprint(lenOfArray)+"]")
				tempValue, tempDataType, _, err := jsonparser.Get(jsondata, iterateKey...)
				if err != nil {
					iterateKey = iterateKey[:len(iterateKey)-1]
					break
				}
				switch tempDataType {
				case 1:
					var newHttpPayload models.HttpPayload
					for _, temp := range iterateKey {
						newHttpPayload.IePath = newHttpPayload.IePath + "/" + temp
					}
					newHttpPayload.IeValueLocation = models.IeLocation_BODY
					newHttpPayload.Value = make(map[string]interface{})
					newHttpPayload.Value[fmt.Sprint(tempDataType)] = string(tempValue)
					httpPayload = append(httpPayload, newHttpPayload)
				case 2:
					var newHttpPayload models.HttpPayload
					for _, temp := range iterateKey {
						newHttpPayload.IePath = newHttpPayload.IePath + "/" + temp
					}
					var temp int
					err := json.Unmarshal(value, &temp)
					if err != nil {
						fmt.Println(err)
					}
					newHttpPayload.IeValueLocation = models.IeLocation_BODY
					newHttpPayload.Value = make(map[string]interface{})
					newHttpPayload.Value[fmt.Sprint(tempDataType)] = temp
					httpPayload = append(httpPayload, newHttpPayload)
				case 5:
					var newHttpPayload models.HttpPayload
					for _, temp := range iterateKey {
						newHttpPayload.IePath = newHttpPayload.IePath + "/" + temp
					}
					var temp bool
					err := json.Unmarshal(value, &temp)
					if err != nil {
						fmt.Println(err)
					}
					newHttpPayload.Value[fmt.Sprint(dataType)] = temp
					newHttpPayload.IeValueLocation = models.IeLocation_BODY
					newHttpPayload.Value = make(map[string]interface{})
					newHttpPayload.Value[fmt.Sprint(tempDataType)] = temp
					httpPayload = append(httpPayload, newHttpPayload)
				case 3, 4:
					jsonparser.ObjectEach(jsondata, objHandler, iterateKey...)
				}
				iterateKey = iterateKey[:len(iterateKey)-1]
				lenOfArray++
			}
		} else {
			var newHttpPayload models.HttpPayload
			for _, temp := range iterateKey {
				newHttpPayload.IePath = newHttpPayload.IePath + "/" + temp
			}
			newHttpPayload.IePath = newHttpPayload.IePath + "/" + string(key)
			newHttpPayload.IeValueLocation = models.IeLocation_BODY
			newHttpPayload.Value = make(map[string]interface{})
			switch dataType {
			case 1:
				newHttpPayload.Value[fmt.Sprint(dataType)] = string(value)
			case 2:
				var temp int
				err := json.Unmarshal(value, &temp)
				if err != nil {
					fmt.Println(err)
				}
				newHttpPayload.Value[fmt.Sprint(dataType)] = temp
			case 5:
				var temp bool
				err := json.Unmarshal(value, &temp)
				if err != nil {
					fmt.Println(err)
				}
				newHttpPayload.Value[fmt.Sprint(dataType)] = temp
			}

			httpPayload = append(httpPayload, newHttpPayload)
			return nil
		}
		iterateKey = iterateKey[:len(iterateKey)-1]
		return nil
	}

	jsonparser.ObjectEach(jsondata, objHandler, iterateKey...)
	return httpPayload
}
