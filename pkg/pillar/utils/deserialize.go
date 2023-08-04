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

func extractFields(t reflect.Type, fieldsMap map[string]bool, criticalFields map[string]bool) {
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		if field.Anonymous {
			// If this is an anonymous field, recursively extract its fields as well.
			extractFields(field.Type, fieldsMap, criticalFields)
		} else {
			// This is a normal field, so just add its name to the map.
			fieldsMap[field.Name] = true
			// Check if the field is mandatory
			tag := field.Tag.Get("mandatory")
			if tag == "true" {
				criticalFields[field.Name] = true
			}
		}
	}
}

// DeserializeToStruct deserializes the given file into the given struct.
// It returns an error if the file is not accessible or if the file does not contain all the necessary fields
// (those that are marked as mandatory="true" in the struct definition).
func DeserializeToStruct(filename string, pointerToStructInstance any) error {
	// Validate the pointerToStructInstance argument
	if reflect.TypeOf(pointerToStructInstance).Kind() != reflect.Ptr {
		return fmt.Errorf("pointerToStructInstance must be a pointer to a struct (it's not a pointer now)")
	}
	structType := reflect.TypeOf(pointerToStructInstance).Elem()
	if structType.Kind() != reflect.Struct {
		return fmt.Errorf("pointerToStructInstance must be a pointer to a struct (it's not to a struct now)")
	}

	data, err := readFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %s", err.Error())
	}

	var dataMap map[string]interface{}
	err = json.Unmarshal(data, &dataMap)
	if err != nil {
		return fmt.Errorf("failed to unmarshal data: %s", err.Error())
	}

	expectedFields := make(map[string]bool)
	criticalFields := make(map[string]bool)
	extractFields(structType, expectedFields, criticalFields)

	err = validateFields(dataMap, expectedFields, criticalFields, filename)
	if err != nil {
		return fmt.Errorf("failed to validate fields: %s", err.Error())
	}

	// Unmarshal from JSON
	err = json.Unmarshal(data, pointerToStructInstance)
	if err != nil {
		return fmt.Errorf("failed to unmarshal data: %s", err.Error())
	}

	return nil
}
