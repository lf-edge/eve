// Copyright (c) 2017-2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	"reflect"
)

func readFile(filename string) ([]byte, error) {
	// Check if the file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		log.Errorf("File %s does not exist", filename)
		return nil, err
	}

	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		log.Errorf("Failed to open file %s, %s", filename, err.Error())
		return nil, err
	}
	defer file.Close()

	// Read the data
	data, err := io.ReadAll(file)
	if err != nil {
		log.Errorf("Failed to read data from file %s, %s", filename, err.Error())
		return nil, err
	}

	return data, nil
}

func validateFields(dataMap map[string]interface{}, expectedFields map[string]bool, criticalFields map[string]bool, filename string) error {
	for k := range dataMap {
		if _, ok := expectedFields[k]; !ok {
			log.Warnf("Unexpected field %s in stored data in %s", k, filename)
		}
	}

	for k := range expectedFields {
		if _, ok := dataMap[k]; !ok {
			if criticalFields[k] {
				errMsg := fmt.Sprintf("Critical field %s missing in stored data in %s", k, filename)
				log.Errorf(errMsg)
				return fmt.Errorf(errMsg)
			}
			log.Warnf("Missing field %s in stored data in %s", k, filename)
		}
	}

	return nil
}

// ExtractFields extracts all fields from the given type and its anonymous fields
// and adds them to the given map. This can be used for a careful deserialization.
func extractFields(t reflect.Type, fieldMap *map[string]bool) {
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		if field.Anonymous {
			// If this is an anonymous field, recursively extract its fields as well.
			extractFields(field.Type, fieldMap)
		} else {
			// This is a normal field, so just add its name to the map.
			(*fieldMap)[field.Name] = true
		}
	}
}

// DeserializeToStruct deserializes the given file into the given struct type.
// It also validates that all mandatory fields in the struct are present in the file. It prints warnings
// for all unexpected fields in the file and for all missing fields in the file that are not mandatory.
func DeserializeToStruct(filename string, structType reflect.Type, criticalFields map[string]bool) (interface{}, error) {
	data, err := readFile(filename)
	if err != nil {
		return nil, err
	}

	var dataMap map[string]interface{}
	err = json.Unmarshal(data, &dataMap)
	if err != nil {
		log.Errorf("Failed to unmarshal data, %s", err.Error())
		return nil, err
	}

	expectedFields := make(map[string]bool)
	extractFields(structType, &expectedFields)

	err = validateFields(dataMap, expectedFields, criticalFields, filename)
	if err != nil {
		return nil, err
	}

	// Unmarshal from JSON
	retStruct := reflect.New(structType).Interface()
	err = json.Unmarshal(data, &retStruct)
	if err != nil {
		log.Errorf("Failed to unmarshal data, %s", err.Error())
		return nil, err
	}

	return retStruct, nil
}
