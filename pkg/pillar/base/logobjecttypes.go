// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"encoding/json"
	"fmt"
	"github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

// LogEventType : Predefined object types
type LogEventType string

const (
	// UnknownType : Invalid event typ
	UnknownType LogEventType = ""
	// LogObjectEventType : Used for logging object state when a change happens
	LogObjectEventType LogEventType = "log"
	// LogRelationEventType : Used for logging the relations between created objects
	LogRelationEventType LogEventType = "relation"
)

// LogObjectType :
type LogObjectType string

// The following is NOT an extensive list.
// Intent is to create a reference list for engineers to get an idea of its usage.
const (
	// UnknownLogType : Invalid log type
	UnknownLogType LogObjectType = ""
	// ImageLogType :
	ImageLogType LogObjectType = "image"
	// AppInstanceStatusLogType :
	AppInstanceStatusLogType LogObjectType = "app_instance_status"
	// AppInstanceConfigLogType :
	AppInstanceConfigLogType LogObjectType = "app_instance_config"
	// AppNetworkStatusLogType :
	AppNetworkStatusLogType LogObjectType = "app_network_status"
	// AppNetworkConfigLogType :
	AppNetworkConfigLogType LogObjectType = "app_network_config"
	// DatastoreConfigLogType :
	DatastoreConfigLogType LogObjectType = "datastore_config"
	// DomainConfigLogType :
	DomainConfigLogType LogObjectType = "domain_config"
	// DomainStatusLogType :
	DomainStatusLogType LogObjectType = "domain_status"
	// DomainMetricLogType :
	DomainMetricLogType LogObjectType = "domain_metric"
	// BaseOsConfigLogType :
	BaseOsConfigLogType LogObjectType = "baseos_config"
	// BaseOsStatusLogType :
	BaseOsStatusLogType LogObjectType = "baseos_status"
	// NodeAgentStatusLogType :
	NodeAgentStatusLogType LogObjectType = "nodeagent_status"
	// ZedAgentStatusLogType :
	ZedAgentStatusLogType LogObjectType = "zedagent_status"
	// ZbootConfigLogType :
	ZbootConfigLogType LogObjectType = "zboot_config"
	// ZbootStatusLogType :
	ZbootStatusLogType LogObjectType = "zboot_status"
	// DownloaderConfigLogType :
	DownloaderConfigLogType LogObjectType = "downloader_config"
	// DownloaderStatusLogType :
	DownloaderStatusLogType LogObjectType = "downloader_status"
	// ResolveConfigLogType :
	ResolveConfigLogType LogObjectType = "resolve_config"
	// ResolveStatusLogType :
	ResolveStatusLogType LogObjectType = "resolve_status"
	// VerifyImageConfigLogType :
	VerifyImageConfigLogType LogObjectType = "verifyimage_config"
	// VerifyImageStatusLogType :
	VerifyImageStatusLogType LogObjectType = "verifyimage_status"
	// ContentTreeConfigLogType :
	ContentTreeConfigLogType LogObjectType = "contenttree_config"
	// ContentTreeStatusLogType :
	ContentTreeStatusLogType LogObjectType = "contenttree_status"
	// DevicePortConfig : object being logged
	DevicePortConfigLogType LogObjectType = "deviceport_config"
	// DevicePortConfigList :
	DevicePortConfigListLogType LogObjectType = "deviceportconfig_list"
	// DeviceNetworkStatus :
	DeviceNetworkStatusLogType LogObjectType = "devicenetwork_status"
	// BlobStatusType:
	BlobStatusLogType LogObjectType = "blob_status"
	// VolumeConfigLogType:
	VolumeConfigLogType LogObjectType = "volume_config"
	// VolumeStatusLogType:
	VolumeStatusLogType LogObjectType = "volume_status"
	// VolumeRefConfigLogType:
	VolumeRefConfigLogType LogObjectType = "volume_ref_config"
	// VolumeRefStatusLogType:
	VolumeRefStatusLogType LogObjectType = "volume_ref_status"
	// VolumeCreatePendingLogType:
	VolumeCreatePendingLogType LogObjectType = "volume_create_pending"
	// ServiceInitType:
	ServiceInitLogType LogObjectType = "service_init"
	// AppAndImageToHashLogType:
	AppAndImageToHashLogType LogObjectType = "app_and_image_to_hash"
	// AppContainerMetricsLogType:
	AppContainerMetricsLogType LogObjectType = "app_container_metric"
	// AssignableAdaptersLogType:
	AssignableAdaptersLogType LogObjectType = "assignable_adapters"
	// PhysicalIOAdapterListLogType:
	PhysicalIOAdapterListLogType LogObjectType = "physical_io_adapter_list"
	// AttestNonceLogType:
	AttestNonceLogType LogObjectType = "attest_nonce"
	// AttestQuoteLogType:
	AttestQuoteLogType LogObjectType = "attest_quote"
	// VaultStatusLogType:
	VaultStatusLogType LogObjectType = "vault_status"
	// CipherBlockStatusLogType:
	CipherBlockStatusLogType LogObjectType = "cipher_block_status"
	// CipherContextLogType:
	CipherContextLogType LogObjectType = "cipher_context"
	// CipherMetricsLogType:
	CipherMetricsLogType LogObjectType = "cipher_metric"
	// ControllerCertLogType:
	ControllerCertLogType LogObjectType = "controller_cert"
	// EdgeNodeCertLogType:
	EdgeNodeCertLogType LogObjectType = "edge_node_cert"
	// HostMemoryLogType:
	HostMemoryLogType LogObjectType = "host_memory"
	// IPFlowLogType:
	IPFlowLogType LogObjectType = "ip_flow"
	// VifIPTrigLogType:
	VifIPTrigLogType LogObjectType = "vif_ip_trig"
	// OnboardingStatusLogType:
	OnboardingStatusLogType LogObjectType = "onboarding_status"
	// NetworkInstanceConfigLogType:
	NetworkInstanceConfigLogType LogObjectType = "network_instance_config"
	// NetworkInstanceStatusLogType:
	NetworkInstanceStatusLogType LogObjectType = "network_instance_status"
	// NetworkInstanceMetricsLogType:
	NetworkInstanceMetricsLogType LogObjectType = "network_instance_metrics"
	// NetworkMetricsLogType:
	NetworkMetricsLogType LogObjectType = "network_metrics"
	// WwanMetricsLogType:
	WwanMetricsLogType LogObjectType = "wwan_metrics"
	// WwanLocationInfoLogType:
	WwanLocationInfoLogType LogObjectType = "wwan_location_info"
	// NetworkXObjectConfigLogType:
	NetworkXObjectConfigLogType LogObjectType = "network_x_object"
	// UUIDToNumLogType:
	UUIDToNumLogType LogObjectType = "uuid_to_num"
	// DiskMetricType:
	DiskMetricType LogObjectType = "disk_metric"
	// AppDiskMetricType:
	AppDiskMetricType LogObjectType = "app_disk_metric"
	// ProcessMetricLogType:
	ProcessMetricLogType LogObjectType = "process_metric"
	// SigUSR1StacksType:
	SigUSR1StacksType LogObjectType = "sigusr1_stacks"
	// FatalStacksType:
	FatalStacksType LogObjectType = "fatal_stacks"
	// MemoryNotificationType
	MemoryNotificationType = "memory_notification"
	// DiskNotificationType
	DiskNotificationType = "disk_notification"
	// AppInterfaceToNumLogType
	AppInterfaceToNumLogType LogObjectType = "app_interface_to_num"
	// EncryptedVaultKeyFromDeviceLogType:
	EncryptedVaultKeyFromDeviceLogType LogObjectType = "encrypted_vault_key_from_device"
	// EncryptedVaultKeyFromControllerLogType:
	EncryptedVaultKeyFromControllerLogType LogObjectType = "encrypted_vault_key_from_controller"
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
	logger      *logrus.Logger
}

// logObjectMap tracks objects for NewLogObject
// Needs to be a unique object for every thing which wants a unique
// source/pid or other field set in LogObject
var logObjectMap = NewLockedStringMap()

// logSourceObjectMap tracks objects for NewSourceLogObject
var logSourceObjectMap = NewLockedStringMap()

// LoggableObject :
type LoggableObject interface {
	LogKey() string
	LogCreate(logBase *LogObject)
	LogModify(logBase *LogObject, old interface{})
	LogDelete(logBase *LogObject)
}

// Make sure we have a separate object for each agent aka log context.
// This is critical to keep e.g., the subscribers and publishers for the same
// objects apart when those subscribers and publishers run in the same process
func (object *LogObject) mapKey(key string) string {
	return fmt.Sprintf("%s:%p", key, object)
}

// NewLogObject :
// objType -> [MANDATORY] volume configuration, app configuration, app status, image etc
// objName -> App instance name, name of file being downloaded etc
// objUUID -> UUID of the object if present (App instance UUID) or Zero/uninitialized UUID if not present
// key     -> [MANDATORY] Key used for storing internal data. This should be the same Key that your LoggableObject.Key()
// would return. LogObject created here and the corresponding LoggableObject are linked using this key.
func NewLogObject(logBase *LogObject, objType LogObjectType, objName string, objUUID uuid.UUID, key string) *LogObject {
	if logBase == nil {
		logrus.Fatalf("No logBase for %s/%s/%s/%s", string(objType),
			objName, objUUID.String(), key)
	}
	if objType == UnknownLogType || len(key) == 0 {
		logrus.Fatal("NewLogObject: objType and key parameters mandatory")
	}
	// Check if we already have an object with the given key
	var object *LogObject
	value, ok := logObjectMap.Load(logBase.mapKey(key))
	if ok {
		object, ok = value.(*LogObject)
		if ok {
			return object
		}
		logrus.Fatalf("NewLogObject: Object found in key map is not of type *LogObject, found: %T", value)
	}

	object = new(LogObject)
	InitLogObject(logBase, object, objType, objName, objUUID, key)

	return object
}

// InitLogObject : Initialize an already allocated LogObject
func InitLogObject(logBase *LogObject, object *LogObject, objType LogObjectType, objName string, objUUID uuid.UUID, key string) {
	if logBase == nil {
		logrus.Fatalf("No logBase for %s/%s/%s/%s", string(objType),
			objName, objUUID.String(), key)
	}
	if objType == UnknownLogType || len(key) == 0 {
		logrus.Fatal("InitLogObject: objType and key parameters mandatory")
	}
	if object == nil {
		logrus.Fatal("InitLogObject: LogObject cannot be nil")
	}
	fields := make(map[string]interface{})
	fields["log_event_type"] = LogObjectEventType
	fields["obj_type"] = objType
	if len(objName) != 0 {
		fields["obj_name"] = objName
	}
	fields["obj_key"] = key
	if !uuid.Equal(objUUID, uuid.UUID{}) {
		fields["obj_uuid"] = objUUID.String()
	}
	object.Fields = fields
	object.logger = logBase.logger
	object.Merge(logBase)
	object.Initialized = true
	logObjectMap.Store(logBase.mapKey(key), object)
}

// NewSourceLogObject : create an object with agentName and agentPid
// Since there might be multiple calls to this for the same agent
// we check for an existing one for the agentName
func NewSourceLogObject(logger *logrus.Logger, agentName string, agentPid int) *LogObject {
	// Check if we already have an object with the given agentName
	var object *LogObject
	value, ok := logSourceObjectMap.Load(agentName)
	if ok {
		object, ok = value.(*LogObject)
		if ok {
			return object
		}
		logrus.Fatalf("NewSourceLogObject: Object found is not of type *LogObject, found: %T",
			value)
	}

	object = new(LogObject)
	object.logger = logger
	object.Initialized = true
	fields := make(map[string]interface{})
	fields["source"] = agentName
	fields["pid"] = agentPid
	object.Fields = fields
	logSourceObjectMap.Store(agentName, object)
	return object
}

// NewRelationObject : Creates a relation object.
// Supposed to be ephemeral and not retained for long.
// Create a new object every time a new relation needs to be expressed.
// relationObjectType -> add a relation or delete an existing relation
// fromObjType        -> Type of the source point of relation
// fromObjName        -> Name of the source point of relation
// toObjType          -> Type of the destination point of relation
// toObjName          -> Name of the destination point of relation
func NewRelationObject(logBase *LogObject, relationObjectType RelationObjectType,
	fromObjType LogObjectType, fromObjNameOrKey string,
	toObjType LogObjectType, toObjNameOrKey string) *LogObject {

	if logBase == nil {
		logrus.Fatalf("No logBase for %s to %s",
			fromObjNameOrKey, toObjNameOrKey)
	}

	object := new(LogObject)
	if object == nil {
		logrus.Fatal("Relation object allocation failed")
	}

	fields := make(map[string]interface{})
	fields["log_event_type"] = LogRelationEventType
	fields["relation_type"] = relationObjectType
	fields["from_obj_type"] = fromObjType
	fields["from_obj_name_or_key"] = fromObjNameOrKey
	fields["to_obj_type"] = toObjType
	fields["to_obj_name_or_key"] = toObjNameOrKey

	object.logger = logBase.logger
	object.Initialized = true
	object.Fields = fields
	object.Merge(logBase)
	return object
}

// LookupLogObject :
func LookupLogObject(mapKey string) *LogObject {
	var object *LogObject
	value, ok := logObjectMap.Load(mapKey)
	if !ok {
		return nil
	}
	object, ok = value.(*LogObject)
	if !ok {
		logrus.Fatalf("LookupLogObject: Object found in key map is not of type *LogObject, found: %T", value)
	}
	return object
}

// EnsureLogObject : Look for log object with given key or create new if we do not already have one.
func EnsureLogObject(logBase *LogObject, objType LogObjectType, objName string, objUUID uuid.UUID, key string) *LogObject {
	if logBase == nil {
		logrus.Fatalf("No logBase for %s/%s/%s/%s", string(objType),
			objName, objUUID.String(), key)
	}
	logObject := LookupLogObject(logBase.mapKey(key))
	if logObject == nil {
		logObject = NewLogObject(logBase, objType, objName, objUUID, key)
	}
	return logObject
}

// DeleteLogObject : Delete log object from internal map
// logBase must be the same object as for calls to EnsureLogObject and NewLogObject
func DeleteLogObject(logBase *LogObject, key string) {
	if logBase == nil {
		logrus.Fatalf("No logBase for %s", key)
	}
	mapKey := logBase.mapKey(key)
	_, ok := logObjectMap.Load(mapKey)
	if !ok {
		// use logBase as logger to show agent in source instead of zedbox
		logBase.Errorf("DeleteLogObject: LogObject with mapKey %s not found in internal map", mapKey)
		return
	}
	logObjectMap.Delete(mapKey)
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
	newLogObject.logger = object.logger
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
