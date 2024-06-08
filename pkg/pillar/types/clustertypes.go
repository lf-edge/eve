package types

import (
	"net"

	uuid "github.com/satori/go.uuid"
)

const (
	ClusterPubPort = "12345"
)

// ENClusterAPIConfig XXX temp struct from configitem from controller
type ENClusterAPIConfig struct {
	ClusterName           string
	ClusterID             string
	ClusterInterface      string
	ClusterIPPrefix       string
	IsWorkerNode          bool
	JoinServerIP          string
	EncryptedClusterToken string
}

type EdgeNodeClusterConfig struct {
	ClusterName           string
	ClusterID             UUIDandVersion
	ClusterInterface      string
	ClusterIPPrefix       net.IPNet
	IsWorkerNode          bool
	JoinServerIP          net.IP
	BootstrapNode         bool
	EncryptedClusterToken string // XXX a simple string for configitem

	// CipherBlockStatus, for encrypted cluster token data
	CipherToken CipherBlockStatus
}

type ENClusterAppStatus struct {
	AppUUID             uuid.UUID // UUID of the appinstance
	IsDNSet             bool      // DesignatedNodeID is set for this node
	ScheduledOnThisNode bool      // App is running on this device
	StatusRunning       bool      // Status of the app in "Running" state
}

func (config EdgeNodeClusterConfig) Key() string {
	return config.ClusterID.UUID.String()
}

type EdgeNodeClusterStatus struct {
	ClusterName           string
	ClusterID             UUIDandVersion
	ClusterInterface      string
	ClusterIPPrefix       net.IPNet
	IsWorkerNode          bool
	JoinServerIP          net.IP
	BootstrapNode         bool
	EncryptedClusterToken string // XXX a simple string for now

	Error ErrorDescription
}

type EncPubHeader struct {
	SenderUUID uuid.UUID
	TypeNumber EncPubConfigType
	TypeName   string
	TypeKey    string
	AgentName  string
	OpType     EncPubOpType
}

// redefine the etworkInstanceConfig for cluster pubsub
type EncNetworkInstanceConfig struct {
	NetworkInstanceConfig
}

type EncPubToRemoteData struct {
	Header    EncPubHeader // containers the meta data of the publication
	AgentData []byte       // gob encoded agent publication data
}

type EncPubConfigType int

const (
	EncNetInstConfig EncPubConfigType = iota + 1
	EncVolumeConfig
	EncAppInstConfig
	EncDataStoreConfig
	EncContentTreeConfig
)

type EncPubOpType int

const (
	EncPubOpCreate EncPubOpType = iota + 1
	EncPubOpModify
	EncPubOpDelete
)
