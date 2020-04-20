// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package agentlog

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
)

// LogObject : Holds all key values pairs to be logged later
type LogObject struct {
	fields map[string]interface{}
}

// NewLogObject :
// objType -> log, action, relation etc
// objName -> App instance name, name of file being downloaded etc
// objUUID -> UUID of the object if present (App instance UUID) or UUID of parent object
func NewLogObject(objType string, objName string, objUUID string) *LogObject {
	fields := make(map[string]interface{})
	fields["obj_type"] = objType
	fields["obj_name"] = objName
	fields["obj_uuid"] = objUUID

	return &LogObject{fields: fields}
}

// AddField : Add a key value pair to be logged
func (object *LogObject) AddField(key string, value interface{}) {
	object.fields[key] = value
}

// AddCompositeField : Add a structure/map to be logged
func (object *LogObject) AddCompositeField(key string, value interface{}) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	itemMap := make(map[string]interface{})
	err = json.Unmarshal(b, &itemMap)
	if err != nil {
		return err
	}
	object.AddFields(itemMap)
	return nil
}

// AddFields : Values of exiting keys in the object will be overwritten with new values passed
func (object *LogObject) AddFields(fields map[string]interface{}) {
	for key, value := range fields {
		object.fields[key] = value
	}
}

// Merge :
// Values of existing fields in destination object will be overwritten with values
// from source object.
func (object *LogObject) Merge(source *LogObject) *LogObject {
	for key, value := range source.fields {
		object.fields[key] = value
	}
	return object
}

// Clone : Create a clone from an existing Log object
func (object *LogObject) Clone() *LogObject {
	newLogObject := &LogObject{
		fields: make(map[string]interface{}),
	}
	for key, value := range object.fields {
		newLogObject.fields[key] = value
	}
	return newLogObject
}

// CloneAndAddField : Add key value pair to a cloned log object
func (object *LogObject) CloneAndAddField(key string, value interface{}) *LogObject {
	newLogObject := object.Clone()
	newLogObject.AddField(key, value)
	return newLogObject
}

// CloneAndAddCompositeField : Add composite structure to a cloned log object
func (object *LogObject) CloneAndAddCompositeField(key string, value interface{}) *LogObject {
	newLogObject := object.Clone()
	newLogObject.AddCompositeField(key, value)
	return newLogObject
}

// CloneAndAddFields : Add additional fields to a cloned log object
func (object *LogObject) CloneAndAddFields(fields map[string]interface{}) *LogObject {
	newLogObject := object.Clone()
	newLogObject.AddFields(fields)
	return newLogObject
}

// CloneAndMerge : Merge source into a cloned log object
func (object *LogObject) CloneAndMerge(source *LogObject) *LogObject {
	newLogObject := object.Clone()
	newLogObject.Merge(source)
	return newLogObject
}

// Debug :
func (object *LogObject) Debug(args ...interface{}) {
	log.WithFields(object.fields).Debug(args...)
}

// Print :
func (object *LogObject) Print(args ...interface{}) {
	log.WithFields(object.fields).Print(args...)
}

// Info :
func (object *LogObject) Info(args ...interface{}) {
	log.WithFields(object.fields).Info(args...)
}

// Warn :
func (object *LogObject) Warn(args ...interface{}) {
	log.WithFields(object.fields).Warn(args...)
}

// Warning :
func (object *LogObject) Warning(args ...interface{}) {
	log.WithFields(object.fields).Warning(args...)
}

// Error :
func (object *LogObject) Error(args ...interface{}) {
	log.WithFields(object.fields).Error(args...)
}

// Panic :
func (object *LogObject) Panic(args ...interface{}) {
	log.WithFields(object.fields).Panic(args...)
}

// Fatal :
func (object *LogObject) Fatal(args ...interface{}) {
	log.WithFields(object.fields).Fatal(args...)
}

// Debugf :
func (object *LogObject) Debugf(format string, args ...interface{}) {
	log.WithFields(object.fields).Debugf(format, args...)
}

// Infof :
func (object *LogObject) Infof(format string, args ...interface{}) {
	log.WithFields(object.fields).Infof(format, args...)
}

// Warnf :
func (object *LogObject) Warnf(format string, args ...interface{}) {
	log.WithFields(object.fields).Warnf(format, args...)
}

// Warningf :
func (object *LogObject) Warningf(format string, args ...interface{}) {
	log.WithFields(object.fields).Warningf(format, args...)
}

// Panicf :
func (object *LogObject) Panicf(format string, args ...interface{}) {
	log.WithFields(object.fields).Panicf(format, args...)
}

// Fatalf :
func (object *LogObject) Fatalf(format string, args ...interface{}) {
	log.WithFields(object.fields).Fatalf(format, args...)
}

// Errorf :
func (object *LogObject) Errorf(format string, args ...interface{}) {
	log.WithFields(object.fields).Errorf(format, args...)
}

// Debugln :
func (object *LogObject) Debugln(args ...interface{}) {
	log.WithFields(object.fields).Debugln(args...)
}

// Println :
func (object *LogObject) Println(args ...interface{}) {
	log.WithFields(object.fields).Println(args...)
}

// Infoln :
func (object *LogObject) Infoln(args ...interface{}) {
	log.WithFields(object.fields).Infoln(args...)
}

// Warnln :
func (object *LogObject) Warnln(args ...interface{}) {
	log.WithFields(object.fields).Warnln(args...)
}

// Warningln :
func (object *LogObject) Warningln(args ...interface{}) {
	log.WithFields(object.fields).Warningln(args...)
}

// Errorln :
func (object *LogObject) Errorln(args ...interface{}) {
	log.WithFields(object.fields).Errorln(args...)
}

// Panicln :
func (object *LogObject) Panicln(args ...interface{}) {
	log.WithFields(object.fields).Panicln(args...)
}

// Fatalln :
func (object *LogObject) Fatalln(args ...interface{}) {
	log.WithFields(object.fields).Fatalln(args...)
}
