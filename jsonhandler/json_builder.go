package jsonhandler

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/yangalan0903/openapi/models"
)

func BuildJsonBody(values []models.HttpPayload) []byte {
	obj := make(map[string]interface{})
	for _, value := range values {
		pathSegments := strings.Split(value.IePath, "/")
		pathSegments = pathSegments[1:]
		travaler := obj
		var ok bool
		var arrayTravaler []interface{}
		flag := false
		for idx, segment := range pathSegments {
			if idx == len(pathSegments)-1 {
				if strings.HasPrefix(segment, "[") && strings.HasSuffix(segment, "]") {
					arrayIdx, err := strconv.Atoi(segment[1 : len(segment)-1])
					if err != nil {
						fmt.Println(err)
					}
					if _, exist := value.Value["encBlockIndex"]; exist {
						arrayTravaler[arrayIdx] = value.Value
					} else {
						for _, val := range value.Value {
							arrayTravaler[arrayIdx] = val
						}
					}
					break
				}
				if _, exist := value.Value["encBlockIndex"]; exist {
					travaler[segment] = value.Value
				} else {
					for _, val := range value.Value {
						travaler[segment] = val
					}
				}
				break
			}
			if flag == false {
				if v, exist := travaler[segment]; exist {
					if strings.HasPrefix(pathSegments[idx+1], "[") && strings.HasSuffix(pathSegments[idx+1], "]") {
						arrayIdx, err := strconv.Atoi(pathSegments[idx+1][1 : len(pathSegments[idx+1])-1])
						if err != nil {
							fmt.Println(err)
						}
						arrayTravaler, ok = v.([]interface{})
						if arrayIdx >= len(arrayTravaler) {
							arrayTravaler = append(arrayTravaler, nil)
							travaler[segment] = arrayTravaler
							if !ok {
								fmt.Println("Failed with", v)
								return []byte("")
							}
						}
						flag = true
					} else {
						travaler, ok = v.(map[string]interface{})
						if !ok {
							fmt.Println("Failed with", v)
							return []byte("")
						}
					}
				} else {
					if strings.HasPrefix(pathSegments[idx+1], "[") && strings.HasSuffix(pathSegments[idx+1], "]") {
						var nextArray []interface{}
						nextArray = append(nextArray, nil)
						travaler[segment] = nextArray
						arrayTravaler = nextArray
						flag = true
					} else {
						nextMap := make(map[string]interface{})
						travaler[segment] = nextMap
						travaler = nextMap
					}
				}
			} else {
				arrayIdx, err := strconv.Atoi(segment[1 : len(segment)-1])
				if err != nil {
					fmt.Println(err)
				}
				if strings.HasPrefix(pathSegments[idx+1], "[") && strings.HasSuffix(pathSegments[idx+1], "]") {
					if arrayTravaler[arrayIdx] == nil {
						var nextArray []interface{}
						arrayTravaler[arrayIdx] = nextArray
						arrayTravaler = nextArray
					} else {
						nextArrayIdx, err := strconv.Atoi(pathSegments[idx+1][1 : len(pathSegments[idx+1])-1])
						if err != nil {
							fmt.Println(err)
						}
						nextArrayTravaler := arrayTravaler[arrayIdx].([]interface{})
						if len(nextArrayTravaler) <= nextArrayIdx {
							var nextArray []interface{}
							nextArrayTravaler = append(nextArrayTravaler, nextArray)
							arrayTravaler[arrayIdx] = nextArrayTravaler
							arrayTravaler = arrayTravaler[arrayIdx].([]interface{})
						}
					}
				} else {
					if arrayTravaler[arrayIdx] == nil {
						nextMap := make(map[string]interface{})
						arrayTravaler[arrayIdx] = nextMap
						travaler = nextMap
					} else {
						travaler = arrayTravaler[arrayIdx].(map[string]interface{})
					}
					flag = false
				}
			}
		}
	}
	// buf := &bytes.Buffer{}
	// je := json.NewEncoder(buf)
	// je.Encode(obj)
	jsonObj, _ := json.Marshal(obj)
	return jsonObj
}
