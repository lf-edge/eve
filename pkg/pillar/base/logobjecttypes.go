// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"encoding/json"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// ObjectType : Predefined object types
type ObjectType string

// The following is NOT an extensive list.
// Intent is to create a reference list for engineers to get an idea of its usage.
const (
	UnknownType  ObjectType = ""
	LogType      ObjectType = "log"
	RelationType ObjectType = "relation"
)

// LogObjectType :
type LogObjectType string

const (
	// UnknownLogType : Invalid log type
	UnknownLogType LogObjectType = ""
	// ImageLogType :
	ImageLogType LogObjectType = "image"
	// NetworkInstanceLogType :
	NetworkInstanceLogType LogObjectType = "network_instance"
	// AppInstanceStatusLogType :
	AppInstanceStatusLogType LogObjectType = "app_instance_status"
	// AppInstanceConfigLogType :
	AppInstanceConfigLogType LogObjectType = "app_instance_config"
	// VolumeLogType :
	VolumeLogType LogObjectType = "volume_type"
)

// RelationObjectType :
type RelationObjectType string

const (
	// UnknownRelationType : Invalid relation type
	UnknownRelationType RelationObjectType = ""
	// AddRelationType :
	AddRelationType RelationObjectType = "add_relation"
	// DeleteRelationType :
	DeleteRelationType RelationObjectType = "delete_relation"
)

// LogObject : Holds all key value pairs to be logged later.
type LogObject struct {
	Initialized bool
	Fields      map[string]interface{}
}

var logObjectMap = make(map[string]*LogObject)

// LoggableObject :
type LoggableObject interface {
	LogKey() string
	LogCreate()
	LogModify(old interface{})
	LogDelete()
}

// NewLogObject :
// objType -> [MANDATORY] log, action, relation, app_instance, image etc
// objName -> App instance name, name of file being downloaded etc
// objUUID -> UUID of the object if present (App instance UUID) or UUID of parent object
// key     -> [MANDATORY] Key used for storing internal data. This should be the same Key your LoggableObject.Key()
// would return. LogObject craeted here and the corresponding LoggableObject are linked using this key.
// objType and objName are mandatory parameters
func NewLogObject(objType LogObjectType, objName string, objUUID uuid.UUID, key string) *LogObject {
	if objType == UnknownLogType || len(key) == 0 {
		log.Fatal("NewLogObject: objType and key parameters mandatory")
	}
	// Check if we already have an object with the given key
	object, ok := logObjectMap[key]
	if ok {
		return object
	}

	object = new(LogObject)
	InitLogObject(object, objType, objName, objUUID, key)

	return object
}

// InitLogObject : Initialize an already allocated LogObject
func InitLogObject(object *LogObject, objType LogObjectType, objName string, objUUID uuid.UUID, key string) {
	if objType == UnknownLogType || len(key) == 0 {
		log.Fatal("InitLogObject: objType and key parameters mandatory")
	}
	if object == nil {
		log.Fatal("InitLogObject: LogObject cannot be nil")
	}
	fields := make(map[string]interface{})
	fields["main_type"] = LogType
	fields["obj_type"] = objType
	fields["obj_name"] = objName
	fields["obj_uuid"] = objUUID.String()
	object.Initialized = true
	object.Fields = fields
	logObjectMap[key] = object
}

// NewRelationObject : Creates a relation object.
// Supposed to be ephemeral and not retained for long.
// Create a new object everytime a new relation needs to be expressed.
// relationObjectType -> add a relation or delete an existing relation
// fromObjType        -> Type of the source point of relation
// fromObjName        -> Name of the source point of relation
// toObjType          -> Type of the destination point of relation
// toObjName          -> Name of the destination point of relation
func NewRelationObject(relationObjectType RelationObjectType,
	fromObjType LogObjectType, fromObjNameOrKey string,
	toObjType LogObjectType, toObjNameOrKey string) *LogObject {

	object := new(LogObject)
	if object == nil {
		log.Fatal("Relation object allocation failed")
	}

	fields := make(map[string]interface{})
	fields["main_type"] = RelationType
	fields["relation_type"] = relationObjectType
	fields["from_obj_type"] = fromObjType
	fields["from_obj_name_or_key"] = fromObjNameOrKey
	fields["to_obj_type"] = toObjType
	fields["to_obj_name_or_key"] = toObjNameOrKey

	object.Initialized = true
	object.Fields = fields

	return object
}

// LookupLogObject :
func LookupLogObject(key string) *LogObject {
	object, ok := logObjectMap[key]
	if ok {
		return object
	}
	return nil
}

// EnsureLogObject : Look for log object with given key or create new if we do not already have one.
func EnsureLogObject(objType LogObjectType, objName string, objUUID uuid.UUID, key string) *LogObject {
	logObject := LookupLogObject(key)
	if logObject == nil {
		logObject = NewLogObject(objType, objName, objUUID, key)
	}
	return logObject
}

// DeleteLogObject :
func DeleteLogObject(key string) {
	_, ok := logObjectMap[key]
	if !ok {
		log.Errorf("DeleteLogObject: LogObject with key %s not found in internal map", key)
		return
	}
	delete(logObjectMap, key)
}

// AddField : Add a key value pair to be logged
func (object *LogObject) AddField(key string, value interface{}) *LogObject {
	object.Fields[key] = value
	return object
}

// AddCompositeField : Add a structure/map to be logged
func (object *LogObject) AddCompositeField(key string, value interface{}) (*LogObject, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	itemMap := make(map[string]interface{})
	err = json.Unmarshal(b, &itemMap)
	if err != nil {
		return nil, err
	}
	object.AddFields(itemMap)
	return object, nil
}

// AddFields : Values of exiting keys in the object will be overwritten with new values passed
func (object *LogObject) AddFields(fields map[string]interface{}) *LogObject {
	for key, value := range fields {
		object.Fields[key] = value
	}
	return object
}

// Merge :
// Values of existing fields in destination object will be overwritten with values
// from source object.
func (object *LogObject) Merge(source *LogObject) *LogObject {
	for key, value := range source.Fields {
		object.Fields[key] = value
	}
	return object
}

// Clone : Create a clone from an existing Log object
func (object *LogObject) Clone() *LogObject {
	newLogObject := new(LogObject)
	newLogObject.Fields = make(map[string]interface{})
	for key, value := range object.Fields {
		newLogObject.Fields[key] = value
	}
	newLogObject.Initialized = true
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
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Debug(args...)
}

// Print :
func (object *LogObject) Print(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Print(args...)
}

// Info :
func (object *LogObject) Info(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Info(args...)
}

// Warn :
func (object *LogObject) Warn(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Warn(args...)
}

// Warning :
func (object *LogObject) Warning(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Warning(args...)
}

// Panic :
func (object *LogObject) Panic(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Panic(args...)
}

// Fatal :
func (object *LogObject) Fatal(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Fatal(args...)
}

// Debugf :
func (object *LogObject) Debugf(format string, args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Debugf(format, args...)
}

// Infof :
func (object *LogObject) Infof(format string, args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Infof(format, args...)
}

// Warnf :
func (object *LogObject) Warnf(format string, args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Warnf(format, args...)
}

// Warningf :
func (object *LogObject) Warningf(format string, args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Warningf(format, args...)
}

// Panicf :
func (object *LogObject) Panicf(format string, args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Panicf(format, args...)
}

// Fatalf :
func (object *LogObject) Fatalf(format string, args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Fatalf(format, args...)
}

// Errorf :
func (object *LogObject) Errorf(format string, args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Errorf(format, args...)
}

// Debugln :
func (object *LogObject) Debugln(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Debugln(args...)
}

// Println :
func (object *LogObject) Println(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Println(args...)
}

// Infoln :
func (object *LogObject) Infoln(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Infoln(args...)
}

// Warnln :
func (object *LogObject) Warnln(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Warnln(args...)
}

// Warningln :
func (object *LogObject) Warningln(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Warningln(args...)
}

// Errorln :
func (object *LogObject) Errorln(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Errorln(args...)
}

// Panicln :
func (object *LogObject) Panicln(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Panicln(args...)
}

// Fatalln :
func (object *LogObject) Fatalln(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Fatalln(args...)
}
