// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
)

type LargeNested struct {
	LargeNestedData []byte `json:"pubsub-large-LargeNestedData"`
}

type LargeWithNested struct {
	LargeTop    []byte `json:"pubsub-large-LargeTop"`
	LargeNested LargeNested
}

func TestRemoveAndAddLarge(t *testing.T) {
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "test", 1234)
	// Run in a unique directory
	rootPath, err := os.MkdirTemp("", "remove_large_test")
	if err != nil {
		t.Fatalf("TempDir failed: %s", err)
	}
	defer os.RemoveAll(rootPath)

	originalObject := LargeWithNested{LargeNested: LargeNested{LargeNestedData: []byte{1}}, LargeTop: []byte{2}}

	originb, err := json.Marshal(originalObject)
	if err != nil {
		t.Fatalf("cannot marshal %v: %s", originalObject, err)
	}
	originb, err = writeAndRemoveLarge(log, originb, rootPath)
	if err != nil {
		t.Fatal(err)
	}

	newTree := jsonTree{}

	err = json.Unmarshal(originb, &newTree)
	if err != nil {
		t.Fatal(err)
	}

	largeTop, ok := newTree[tagFile+"LargeTop"]
	if !ok {
		t.Fatalf("cannot find LargeTop after writeAndRemoveLarge: %v", newTree)
	}
	largeTopString, isLargeTopString := largeTop.(string)
	if !isLargeTopString {
		t.Fatalf("LargeTop %T is not a string", largeTop)
	}
	if !strings.Contains(largeTopString, rootPath) {
		t.Errorf("cannot find directory (%s) in LargeTop %s", rootPath, largeTopString)
	}

	largeNested, ok := newTree["LargeNested"]
	if !ok {
		t.Fatalf("cannot find LargeNested after writeAndRemoveLarge: %v", newTree)
	}
	largeNestedObj, isLargeNestedObjMap := largeNested.(map[string]interface{})
	if !isLargeNestedObjMap {
		t.Fatalf("LargeNested %T is not a map", largeNested)
	}
	largeNestedData, ok := largeNestedObj[tagFile+"LargeNestedData"]
	if !ok {
		t.Fatalf("cannot find %s after writeAndRemoveLarge: %v", tagFile+"LargeNestedData", largeNestedObj)
	}
	largeNestedDataString, isLargeNestedDataString := largeNestedData.(string)
	if !isLargeNestedDataString {
		t.Fatalf("%s %T is not a string", tagFile+"LargeNestedData", largeNestedData)
	}
	if !strings.Contains(largeNestedDataString, rootPath) {
		t.Errorf("cannot find directory (%s) in %s %s", rootPath, tagFile+"LargeNestedData", largeNestedDataString)
	}

	originb, err = readAddLarge(log, originb)
	if err != nil {
		t.Fatal(err)
	}

	newObject := LargeWithNested{}

	err = json.Unmarshal(originb, &newObject)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(originalObject, newObject) {
		t.Fatalf("objects are not equal: %v %v", originalObject, newObject)
	}
}

type EmbeddedWithLarge struct {
	EmbeddedLargeData [][]byte `json:"pubsub-large-EmbeddedLargeData"`
}

type LargeInsideArray struct {
	SmallData string
	LargeData [][]byte `json:"pubsub-large-LargeData"`
	EmbeddedWithLarge
}

type LargeWithArray struct {
	LargeTop            []byte `json:"pubsub-large-LargeTop"`
	ArrayWithLargeData  []LargeInsideArray
	ArrayWithLargeData2 []LargeInsideArray
}

func TestRemoveAndAddLargeWithArray(t *testing.T) {
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "test", 1234)
	// Run in a unique directory
	rootPath, err := os.MkdirTemp("", "remove_large_test_with_array")
	if err != nil {
		t.Fatalf("TempDir failed: %s", err)
	}
	defer os.RemoveAll(rootPath)

	originalObject := LargeWithArray{
		LargeTop: []byte{2},
		ArrayWithLargeData: []LargeInsideArray{
			{
				SmallData: "test",
				LargeData: [][]byte{{1, 2, 3}, {4, 5, 6}},
				EmbeddedWithLarge: EmbeddedWithLarge{
					EmbeddedLargeData: [][]byte{{7, 8, 9}},
				},
			},
			{
				SmallData: "small",
				LargeData: [][]byte{{1, 0, 1, 0}},
				EmbeddedWithLarge: EmbeddedWithLarge{
					EmbeddedLargeData: [][]byte{{2}},
				},
			},
		},
		ArrayWithLargeData2: []LargeInsideArray{
			{
				LargeData: [][]byte{{10}},
				EmbeddedWithLarge: EmbeddedWithLarge{
					EmbeddedLargeData: [][]byte{{3}, {6}},
				},
			},
		},
	}

	originb, err := json.Marshal(originalObject)
	if err != nil {
		t.Fatalf("cannot marshal %v: %s", originalObject, err)
	}
	originb, err = writeAndRemoveLarge(log, originb, rootPath)
	if err != nil {
		t.Fatal(err)
	}

	newTree := jsonTree{}

	err = json.Unmarshal(originb, &newTree)
	if err != nil {
		t.Fatal(err)
	}

	largeTop, ok := newTree[tagFile+"LargeTop"]
	if !ok {
		t.Fatalf("cannot find LargeTop after writeAndRemoveLarge: %v", newTree)
	}
	largeTopString, isLargeTopString := largeTop.(string)
	if !isLargeTopString {
		t.Fatalf("LargeTop %T is not a string", largeTop)
	}
	if !strings.Contains(largeTopString, rootPath) {
		t.Errorf("cannot find directory (%s) in LargeTop %s", rootPath, largeTopString)
	}

	arrays := []string{"ArrayWithLargeData", "ArrayWithLargeData2"}
	for _, array := range arrays {
		arrayWithLarge, ok := newTree[array]
		if !ok {
			t.Fatalf("cannot find %s after writeAndRemoveLarge: %v", array, newTree)
		}
		arrayObj, isArray := arrayWithLarge.([]interface{})
		if !isArray {
			t.Fatalf("%s %T is not a list", array, arrayWithLarge)
		}
		for i := range arrayObj {
			arrayEntryObj, isMap := arrayObj[i].(map[string]interface{})
			if !isMap {
				t.Fatalf("%s[%d] (%T) is not a map", array, i, arrayObj[i])
			}
			fields := []string{tagFile + "LargeData", tagFile + "EmbeddedLargeData"}
			for _, field := range fields {
				largeData, ok := arrayEntryObj[field]
				if !ok {
					t.Fatalf("cannot find %s after writeAndRemoveLarge: %v", field, arrayEntryObj)
				}
				largeDataFilePath, isString := largeData.(string)
				if !isString {
					t.Fatalf("%s %T is not a string", field, largeData)
				}
				if !strings.Contains(largeDataFilePath, rootPath) {
					t.Errorf("cannot find directory (%s) in %s %s", rootPath, field, largeDataFilePath)
				}
			}
		}
	}

	originb, err = readAddLarge(log, originb)
	if err != nil {
		t.Fatal(err)
	}

	newObject := LargeWithArray{}

	err = json.Unmarshal(originb, &newObject)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(originalObject, newObject) {
		t.Fatalf("objects are not equal: %v vs. %v", originalObject, newObject)
	}
}
