package jsonhandler_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/yangalan0903/sepp/jsonhandler"
)

type personalInfo struct {
	Name   *NameType  `json:"name"`
	ID     string     `json:"id"`
	Title  string     `json:"title"`
	Family FamilyInfo `json:"familyInfo"`
}

type NameType struct {
	First    string `json:"first"`
	Last     string `json:"last"`
	FullName string `json:"fullName"`
}

type FamilyInfo struct {
	Number   int  `json:"number"`
	Single   bool `json:"single"`
	Relative []NameType
	Test     []TestData
}

type TestData struct {
	TestString []string
}

func TestJsonBuilder(t *testing.T) {
	var data personalInfo
	data.ID = "0866020"
	data.Title = "master student"
	data.Name = &NameType{
		First:    "Alan",
		Last:     "Yang",
		FullName: "Alan Yang",
	}
	sister := NameType{
		First:    "Judy",
		Last:     "Yang",
		FullName: "Judy Yang",
	}
	father := NameType{
		First:    "liang-len",
		Last:     "Yang",
		FullName: "liang-len Yang",
	}
	data.Family = FamilyInfo{
		Number: 4,
		Single: false,
	}
	data.Family.Relative = append(data.Family.Relative, sister, father)
	var test TestData
	test.TestString = append(test.TestString, "123", "234")
	data.Family.Test = append(data.Family.Test, test)
	jsonData, _ := json.Marshal(data)
	temp := jsonhandler.ParseJsonBody(jsonData)
	fmt.Println(temp)
	newData := jsonhandler.BuildJsonBody(temp)
	var new personalInfo
	if err := json.Unmarshal(newData, &new); err != nil {
		fmt.Println("62:", err)
	}
	pass := reflect.DeepEqual(data, new)
	fmt.Println(pass)
	fmt.Println("30:\n", hex.Dump(jsonData))
	fmt.Println("31:\n", hex.Dump(newData))
}
