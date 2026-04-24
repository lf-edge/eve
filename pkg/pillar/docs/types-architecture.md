# Architecture of `pkg/pillar/types`

This document describes the structure, relationships, and semantics of every
significant type in `pkg/pillar/types`. It is intended as the authoritative
reference for writing Go unit tests for this package.

The package has 61 source files and ~747 exported functions. Approximately
580 of those functions are currently uncovered by tests. Almost all
uncovered functions are accessor methods, constructors, `String()` /
`Key()` helpers, and enum-to-protobuf converters — mechanical work that
unit tests can cover exhaustively without a running EVE system.

---

## Contents

1. [Package conventions](#1-package-conventions)
2. [Error tracking hierarchy](#2-error-tracking-hierarchy)
3. [Core enums used across many types](#3-core-enums-used-across-many-types)
4. [Pubsub key infrastructure](#4-pubsub-key-infrastructure)
5. [App instance types](#5-app-instance-types)
6. [Volume and content types](#6-volume-and-content-types)
7. [Network types — app networking](#7-network-types--app-networking)
8. [Device port config and network status](#8-device-port-config-and-network-status)
9. [Hardware / IO adapter types](#9-hardware--io-adapter-types)
10. [Security types](#10-security-types)
11. [Global configuration types](#11-global-configuration-types)
12. [Download, verify, and blob types](#12-download-verify-and-blob-types)
13. [Cluster and Kubernetes types](#13-cluster-and-kubernetes-types)
14. [Metrics and monitoring types](#14-metrics-and-monitoring-types)
15. [Utility and infrastructure types](#15-utility-and-infrastructure-types)
16. [Standalone functions](#16-standalone-functions)
17. [Testing guide](#17-testing-guide)

---

## 1. Package conventions

### Pubsub lifecycle interface

Every config/status object participates in pubsub. The implicit interface is:

```go
Key() string
LogCreate(logBase *base.LogObject)
LogModify(logBase *base.LogObject, old interface{})
LogDelete(logBase *base.LogObject)
LogKey() string
```

`Key()` is the unique pubsub identifier. `LogKey()` prefixes the key with a
log type constant (e.g., `"VolumeConfig-<uuid>#<gen>"`).

`LogCreate`, `LogModify`, and `LogDelete` are called by pubsub when objects
are published, changed, or removed. They call `base.NewLogObject` /
`base.EnsureLogObject` / `base.DeleteLogObject`.

### Config vs Status pairs

Most subsystems define a `XxxConfig` (published by the controller-side agent)
and `XxxStatus` (published back by the worker agent). Config drives intent;
Status reflects reality. Status types almost always embed `ErrorAndTime` or
`ErrorAndTimeWithSource`.

### Generation counters

`VolumeConfig` and `VolumeStatus` use composite keys:
`UUID#(GenerationCounter+LocalGenerationCounter)`. This allows tracking
multiple generations of the same volume simultaneously during updates.

---

## 2. Error tracking hierarchy

Defined in `errortime.go`.

### Constants

```go
RetryCountWarning = 10
RetryTimeWarning  = time.Hour
RetryCountError   = 20
RetryTimeError    = 10 * time.Hour
```

### `ErrorSeverity` (int32)

```go
ErrorSeverityUnspecified ErrorSeverity = 0
ErrorSeverityNotice      ErrorSeverity = 1
ErrorSeverityWarning     ErrorSeverity = 2
ErrorSeverityError       ErrorSeverity = 3
```

```go
func GetErrorSeverity(retryCount int, timeSpend time.Duration) ErrorSeverity
```

Returns `ErrorSeverityNotice` (< 10 retries / < 1h), `ErrorSeverityWarning`
(10–20 retries / 1–10h), or `ErrorSeverityError` (> 20 retries / > 10h).

### `ErrorEntityType` (int32)

```go
ErrorEntityUnspecified   ErrorEntityType = 0
ErrorEntityBaseOs        ErrorEntityType = 1
ErrorEntitySystemAdapter ErrorEntityType = 2
ErrorEntityVault         ErrorEntityType = 3
ErrorEntityAttestation   ErrorEntityType = 4
ErrorEntityAppInstance   ErrorEntityType = 5
ErrorEntityPort          ErrorEntityType = 6
ErrorEntityNetwork       ErrorEntityType = 7
ErrorEntityNetworkInstance ErrorEntityType = 8
ErrorEntityContentTree   ErrorEntityType = 9
ErrorEntityContentBlob   ErrorEntityType = 10
ErrorEntityVolume        ErrorEntityType = 11
```

### `ErrorEntity`

```go
type ErrorEntity struct {
    EntityType ErrorEntityType
    EntityID   string  // UUID, SHA, or other unique ID
}
```

### `ErrorDescription`

The leaf error type. Embedded by `ErrorAndTime` and `ErrorAndTimeWithSource`.

```go
type ErrorDescription struct {
    Error               string
    ErrorTime           time.Time
    ErrorSeverity       ErrorSeverity
    ErrorRetryCondition string
    ErrorEntities       []*ErrorEntity
}
```

```go
// Sets the error. Panics if Error string is empty.
// Defaults ErrorSeverity to ErrorSeverityError if unspecified.
// Defaults ErrorTime to time.Now() if zero.
func (ed *ErrorDescription) SetErrorDescription(errDescription ErrorDescription)

// Converts to protobuf info.ErrorInfo. Returns nil if ErrorTime is zero.
func (ed *ErrorDescription) ToProto() *info.ErrorInfo
```

### `ErrorAndTime`

Embeds `ErrorDescription`. Used by types that track a single error source.

```go
type ErrorAndTime struct {
    ErrorDescription
}
```

```go
// Deprecated: use SetErrorDescription instead.
func (etPtr *ErrorAndTime) SetErrorNow(errStr string)
func (etPtr *ErrorAndTime) SetError(errStr string, errorTime time.Time)

func (etPtr *ErrorAndTime) ClearError()
func (etPtr *ErrorAndTime) HasError() bool
```

### `ErrorAndTimeWithSource`

Extends `ErrorAndTime` with a source type tag, enabling selective clearing.
Used by types that can receive errors from multiple upstream agents
(e.g., `VolumeStatus` receives errors from both downloader and verifier).

```go
type ErrorAndTimeWithSource struct {
    ErrorSourceType string
    ErrorDescription
}
```

```go
// Deprecated variants:
func (etsPtr *ErrorAndTimeWithSource) SetError(errStr string, errTime time.Time)
func (etsPtr *ErrorAndTimeWithSource) SetErrorWithSource(errStr string, source interface{}, errTime time.Time)

// Preferred:
func (etsPtr *ErrorAndTimeWithSource) SetErrorWithSourceAndDescription(
    errDescription ErrorDescription, source interface{})

// source must be a struct value (not pointer, int, bool, or map).
// Strings are also accepted (for passing ErrorSourceType from another object).
func (etsPtr *ErrorAndTimeWithSource) IsErrorSource(source interface{}) bool
func (etsPtr *ErrorAndTimeWithSource) ClearErrorWithSource()
func (etsPtr *ErrorAndTimeWithSource) HasError() bool
```

**Invariant:** `source` passed to `SetErrorWithSource` / `IsErrorSource` must
not be a pointer, int, bool, or map. Passing a pointer panics via
`logrus.Fatalf`. The stored `ErrorSourceType` is `reflect.TypeOf(source).String()`.

### Error types in `errors.go`

Two sentinel error types (implement `error` interface):

```go
type IPAddrNotAvailError struct { IfName string }
func (e *IPAddrNotAvailError) Error() string
// returns: "interface <IfName>: no suitable IP address available"

type DNSNotAvailError struct { IfName string }
func (e *DNSNotAvailError) Error() string
// returns: "interface <IfName>: no DNS server available"
```

---

## 3. Core enums used across many types

### `SwState` (`types.go`)

Tracks the lifecycle state of app instances, volumes, content trees, and blobs.
Starts at 100 to distinguish from `info.ZSwState` protobuf values.

```go
type SwState uint8

const (
    INITIAL       SwState = iota + 100
    RESOLVING_TAG          // resolving an image tag
    RESOLVED_TAG           // tag resolved (or failed)
    DOWNLOADING
    DOWNLOADED
    VERIFYING
    VERIFIED
    LOADING
    LOADED
    CREATING_VOLUME
    CREATED_VOLUME
    INSTALLED       // available to activate
    AWAITNETWORKINSTANCE
    START_DELAYED   // honoring StartDelay
    BOOTING
    RUNNING
    PAUSING
    PAUSED
    HALTING
    HALTED
    BROKEN   // domain alive but device model failed; maps to ZSwState_HALTING
    UNKNOWN  // maps to ZSwState_RUNNING
    PENDING
    SCHEDULING
    FAILED
    REMOTELOADED  // content loaded on another cluster node
    MAXSTATE
)
```

```go
func (state SwState) String() string
func (state SwState) ZSwState() info.ZSwState
```

**Key mapping notes for `ZSwState()`:**

- `PAUSING` → `ZSwState_RUNNING` (controllers don't support resumable pause)
- `PAUSED` → `ZSwState_INSTALLED`
- `BROKEN` → `ZSwState_HALTING`
- `UNKNOWN` → `ZSwState_RUNNING`
- `REMOTELOADED` → `ZSwState_LOADED`
- State `0` → proto `0`

### `TriState` (`types.go`)

Three-valued boolean for optional settings.

```go
type TriState uint8

const (
    TS_NONE     TriState = iota
    TS_DISABLED
    TS_ENABLED
)

func ParseTriState(value string) (TriState, error)
// Accepts: "none", "enabled"/"enable"/"on", "disabled"/"disable"/"off"
// Returns error for any other string.

func FormatTriState(state TriState) string
// Returns: "none", "enabled", "disabled"
// Calls logrus.Fatalf for invalid values.
```

### `DPCState` (`dpc.go`)

Tracks DPC (Device Port Config) verification progress.

```go
type DPCState uint8

const (
    DPCStateNone             DPCState = iota
    DPCStateFail
    DPCStateFailWithIPAndDNS
    DPCStateSuccess
    DPCStateIPDNSWait
    DPCStatePCIWait
    DPCStateIntfWait
    DPCStateRemoteWait
    DPCStateAsyncWait
    DPCStateWwanWait
)

func (status DPCState) String() string
func (status DPCState) Describe() string  // human-readable sentence
func (status DPCState) InProgress() bool
// InProgress() == true for: IPDNSWait, PCIWait, IntfWait, AsyncWait, WwanWait
// InProgress() == false for: None, Fail, FailWithIPAndDNS, Success, RemoteWait
```

### `SenderStatus` (`global.go`)

Classifies HTTP/HTTPS controller communication failures.

```go
type SenderStatus uint8

const (
    SenderStatusNone                      SenderStatus = iota
    SenderStatusRefused                   // ECONNREFUSED
    SenderStatusUpgrade                   // HTTP 503, controller upgrading
    SenderStatusCertInvalid               // Server cert expired or NotBefore
    SenderStatusCertMiss                  // Unknown senderCertHash
    SenderStatusSignVerifyFail            // Envelope signature failed
    SenderStatusAlgoFail                  // Unsupported hash algorithm
    SenderStatusHashSizeError             // senderCertHash wrong length
    SenderStatusCertUnknownAuthority      // Missing proxy cert
    SenderStatusCertUnknownAuthorityProxy // Proxy configured, cert missing
    SenderStatusNotFound                  // HTTP 404
    SenderStatusForbidden                 // HTTP 403
    SenderStatusFailed                    // Other failure
    SenderStatusDebug                     // Not a failure
)

func (status SenderStatus) String() string
```

### `VolumesSnapshotAction` (`volumetypes.go`)

```go
type VolumesSnapshotAction uint8

const (
    VolumesSnapshotUnspecifiedAction VolumesSnapshotAction = iota
    VolumesSnapshotCreate
    VolumesSnapshotRollback
    VolumesSnapshotDelete
)

func (action VolumesSnapshotAction) String() string
// Returns: "Create", "Rollback", "Delete", "Unspecified"
```

### `SnapshotType` (`zedmanagertypes.go`)

```go
type SnapshotType int32

const (
    SnapshotTypeUnspecified SnapshotType = 0
    SnapshotTypeAppUpdate   SnapshotType = 1
    SnapshotTypeImmediate   SnapshotType = 2
)

func (s SnapshotType) String() string
func (s SnapshotType) ConvertToInfoSnapshotType() info.SnapshotType
```

---

## 4. Pubsub key infrastructure

### `UUIDandVersion` (`zedmanagertypes.go`)

Used as the identification field in most config/status types.

```go
type UUIDandVersion struct {
    UUID    uuid.UUID
    Version string
}
```

No methods; accessed directly by embedding types' `Key()` methods via `UUID.String()`.

### `UuidToNumKey` / `UuidToNum` (`types.go`)

Maps a UUID to an allocated integer (e.g., `appNum`, `bridgeNum`).

```go
type UuidToNumKey struct { UUID uuid.UUID }
func (k UuidToNumKey) Key() string  // UUID.String()

type UuidToNum struct {
    UuidToNumKey
    Number      int
    NumType     string
    CreateTime  time.Time
    LastUseTime time.Time
    InUse       bool
}
```

Implements `objtonum.ObjNumContainer`:

```go
func (info *UuidToNum) New(objKey objtonum.ObjKey) objtonum.ObjNumContainer
func (info *UuidToNum) GetKey() objtonum.ObjKey
func (info *UuidToNum) SetNumber(number int, numberType string)
func (info *UuidToNum) GetNumber() (number int, numberType string)
func (info *UuidToNum) GetTimestamps() (createdAt time.Time, lastUpdatedAt time.Time)
func (info *UuidToNum) SetReservedOnly(reservedOnly bool)  // sets InUse = !reservedOnly
func (info *UuidToNum) IsReservedOnly() bool               // returns !InUse
```

Also implements pubsub lifecycle: `LogCreate`, `LogModify`, `LogDelete`, `LogKey`.

### `AppInterfaceKey` / `AppInterfaceToNum` (`types.go`)

Maps an application interface (identified by network instance UUID, app UUID,
and interface index) to an allocated number used for IP address generation.

```go
type AppInterfaceKey struct {
    NetInstID uuid.UUID `json:"BaseID"`  // json tag kept for upgrade compatibility
    AppID     uuid.UUID
    IfIdx     uint32
}
func (info AppInterfaceKey) Key() string
// returns: "<NetInstID>-<AppID>-<IfIdx>"

// AppInterfaceToNum is an alias for UUIDPairAndIfIdxToNum (the legacy struct name,
// preserved to avoid breaking pubsub topic names during EVE upgrades).
type AppInterfaceToNum = UUIDPairAndIfIdxToNum
```

Implements the same `objtonum.ObjNumContainer` and pubsub interfaces as
`UuidToNum`.

### `UuidsToStrings` (`types.go`)

```go
func UuidsToStrings(uuids []uuid.UUID) []string
```

---

## 5. App instance types

Defined primarily in `zedmanagertypes.go` and `domainmgrtypes.go`.

### `AppInstanceConfig`

Published by `zedagent` to `zedmanager`.

```go
type AppInstanceConfig struct {
    UUIDandVersion    UUIDandVersion
    DisplayName       string
    Errors            []string          // list of parse errors, if any
    FixedResources    VmConfig          // CPU, memory, virtualization mode
    VolumeRefConfigList []VolumeRefConfig
    Activate          bool
    AppNetAdapterList []AppNetAdapterConfig
    IoAdapterList     []IoAdapter
    RestartCmd        AppInstanceOpsCmd
    PurgeCmd          AppInstanceOpsCmd
    CloudInitUserData *string `json:"pubsub-large-CloudInitUserData"`
    CipherBlockStatus CipherBlockStatus
    MetaDataType      MetaDataType
    ProfileList       []string
    Delay             time.Duration
    Service           bool
    CloudInitVersion  uint32
    Snapshot          SnapshotConfig
    AllowToDiscover   bool
    IsDesignatedNodeID bool
    AffinityType      zcommon.AppAffinityType
    DeploymentType    AppRuntimeType
    ControllerBootOrder []AppBootConfig
    BootOrderSource   BootOrderSource
}

func (config AppInstanceConfig) Key() string     // UUID.String()
func (config AppInstanceConfig) LogCreate(...)
func (config AppInstanceConfig) LogModify(...)
func (config AppInstanceConfig) LogDelete(...)
func (config AppInstanceConfig) LogKey() string
```

### `AppInstanceStatus`

Published by `zedmanager` back to `zedagent`.

```go
type AppInstanceStatus struct {
    UUIDandVersion     UUIDandVersion
    DisplayName        string
    DomainName         string
    Activated          bool
    ActivateInprogress bool
    FixedResources     VmConfig
    VolumeRefStatusList []VolumeRefStatus
    AppNetAdapters     []AppNetAdapterStatus
    BootTime           time.Time
    IoAdapterList      []IoAdapter
    RestartInprogress  Inprogress
    RestartStartedAt   time.Time
    PurgeInprogress    Inprogress
    PurgeStartedAt     time.Time
    State              SwState
    MissingNetwork     bool
    MissingMemory      bool
    NoBootPriority     bool
    ErrorAndTimeWithSource
    StartTime          time.Time
    SnapStatus         SnapshottingStatus
    MemOverhead        uint64
    NoUploadStatsToController bool
    IsDesignatedNodeID bool
}

func (status AppInstanceStatus) Key() string
func (status AppInstanceStatus) LogCreate(...)
func (status AppInstanceStatus) LogModify(...)
func (status AppInstanceStatus) LogDelete(...)
func (status AppInstanceStatus) LogKey() string
func (status AppInstanceStatus) GetAppInterfaceList() []string  // returns VIF names
```

### `Inprogress` enum (`zedmanagertypes.go`)

```go
type Inprogress uint8
const (
    NotInprogress    Inprogress = iota
    DownloadAndVerify
    BringDown
    RecreateVolumes
    BringUp
)
```

### `AppInstanceSummary`

```go
type AppInstanceSummary struct {
    UUIDandVersion UUIDandVersion
    TotalStarting  uint8
    TotalRunning   uint8
    TotalStopping  uint8
    TotalError     uint8
}
func (summary AppInstanceSummary) Key() string  // "global"
```

### `VmConfig` (`domainmgrtypes.go`)

Resource configuration for a VM or container domain.

```go
type VmConfig struct {
    Kernel             string
    Ramdisk            string
    Memory             int         // in kB
    MaxMem             int         // in kB
    VCpus              int
    MaxCpus            int
    RootDev            string
    ExtraArgs          string
    BootLoader         string
    CPUs               string      // CPU affinity mask
    DeviceTree         string
    DtDev              []string
    IRQs               []int
    IOMem              []string
    VirtualizationMode VmMode
    EnableVnc          bool
    VncDisplay         uint32
    VncPasswd          string
    CPUsPinned         bool
    VMMMaxMem          int         // in kB
    EnableVncShimVM    bool
    EnforceNetworkInterfaceOrder bool
    EnableOemWinLicenseKey bool
    DisableVirtualTPM  bool
    BootOrder          zcommon.BootOrder
}
```

### `VmMode` enum (`domainmgrtypes.go`)

```go
type VmMode uint8
const (
    PV      VmMode = iota  // default
    HVM
    Filler
    FML
    NOHYPER
    LEGACY
)
```

### `DomainConfig` (`domainmgrtypes.go`)

Published by `zedmanager` to `domainmgr`. Derived from `AppInstanceConfig`.

```go
type DomainConfig struct {
    UUIDandVersion  UUIDandVersion
    DisplayName     string
    Activate        bool
    AppNum          int
    VmConfig
    DisableLogs     bool
    GPUConfig       string
    DiskConfigList  []DiskConfig
    VifList         []VifInfo
    IoAdapterList   []IoAdapter
    KubeImageName   string
    PurgeCounter    uint32
    IsDNidNode      bool
    AffinityType    zcommon.AppAffinityType
    CloudInitUserData *string `json:"pubsub-large-CloudInitUserData"`
    CipherBlockStatus CipherBlockStatus
    MetaDataType    MetaDataType
    Service         bool
    CloudInitVersion uint32
    OemWindowsLicenseKeyInfo *OemWindowsLicenseKeyInfo
    DeploymentType  AppRuntimeType
}

func (config DomainConfig) Key() string  // UUID.String()
func (config DomainConfig) IsOCIContainer() bool
func (config DomainConfig) GetTaskName() string    // returns DisplayName (for log/debug)
func (config DomainConfig) VirtualizationModeOrDefault() VmMode
// Returns VmConfig.VirtualizationMode or HVM if unset.
```

### `SnapshotConfig` / `SnapshotDesc` / `SnapshotInstanceStatus` / `SnapshottingStatus`

```go
type SnapshotDesc struct {
    SnapshotID   string
    SnapshotType SnapshotType
}

type SnapshotConfig struct {
    ActiveSnapshot string
    MaxSnapshots   uint32
    RollbackCmd    AppInstanceOpsCmd
    Snapshots      []SnapshotDesc
}

type SnapshotInstanceStatus struct {
    Snapshot       SnapshotDesc     `mandatory:"true"`
    Reported       bool
    TimeTriggered  time.Time
    TimeCreated    time.Time
    AppInstanceID  uuid.UUID        `mandatory:"true"`
    ConfigVersion  UUIDandVersion   `mandatory:"true"`
    Error          ErrorDescription
}
func (s SnapshotInstanceStatus) Key() string  // SnapshotID

type SnapshottingStatus struct {
    MaxSnapshots                   uint32
    RequestedSnapshots             []SnapshotDesc
    AvailableSnapshots             []SnapshotInstanceStatus
    SnapshotsToBeDeleted           []string
    PreparedVolumesSnapshotConfigs []VolumesSnapshotConfig
    SnapshotTakenType              SnapshotType
    HasRollbackRequest             bool
    ActiveSnapshot                 string
    RollbackInProgress             bool
}
```

### `AppContainerMetrics` / `AppContainerStats` (`zedroutertypes.go`)

```go
type AppContainerMetrics struct {
    UUIDandVersion UUIDandVersion
    CollectTime    time.Time
    StatsList      []AppContainerStats
}
func (acMetric AppContainerMetrics) Key() string  // UUID.String()

type AppContainerStats struct {
    ContainerName  string
    Status         string
    Pids           uint32
    Uptime         int64   // nanoseconds since container start
    CPUTotal       uint64  // nanoseconds of CPU used
    SystemCPUTotal uint64  // total system CPU in nanoseconds
    UsedMem        uint32  // MBytes
    AllocatedMem   uint32  // MBytes
    TxBytes        uint64
    RxBytes        uint64
    ReadBytes      uint64  // MBytes (disk)
    WriteBytes     uint64  // MBytes (disk)
}
```

### `AppBootConfig` / `AppBootInfo` / `AppAndImageToHash`

```go
type AppBootConfig struct {
    AppUUID     uuid.UUID
    DisplayName string
    BootOrder   uint32
}

type BootOrderSource int32
// (enum constants defined in zedmanagertypes.go)

type AppBootInfo struct {
    AppUUID     uuid.UUID
    DisplayName string
    BootOrder   uint32
    Source      BootOrderSource
}

type AppAndImageToHash struct {
    AppUUID     uuid.UUID
    ImageID     uuid.UUID
    Hash        string
    PurgeCounter uint32
}
func (aih AppAndImageToHash) Key() string  // "UUID/ImageID" or "UUID/ImageID/PurgeCounter"
```

---

## 6. Volume and content types

### `VolumeConfig` (`volumetypes.go`)

```go
type VolumeConfig struct {
    VolumeID               uuid.UUID
    ContentID              uuid.UUID
    VolumeContentOriginType zconfig.VolumeContentOriginType
    MaxVolSize             uint64
    ReadOnly               bool
    GenerationCounter      int64
    LocalGenerationCounter int64
    Encrypted              bool
    DisplayName            string
    HasNoAppReferences     bool
    Target                 zconfig.Target
    CustomMeta             string
    IsReplicated           bool
    IsNativeContainer      bool
}

func (config VolumeConfig) Key() string
// "<VolumeID>#<GenerationCounter+LocalGenerationCounter>"
```

### `VolumeStatus` (`volumetypes.go`)

```go
type volumeSubState uint8
const (
    VolumeSubStateInitial    volumeSubState = iota
    VolumeSubStatePreparing
    VolumeSubStatePrepareDone
    VolumeSubStateCreated
    VolumeSubStateDeleting
)

type VolumeStatus struct {
    VolumeID               uuid.UUID
    ContentID              uuid.UUID
    VolumeContentOriginType zconfig.VolumeContentOriginType
    MaxVolSize             uint64
    ReadOnly               bool
    GenerationCounter      int64
    LocalGenerationCounter int64
    Encrypted              bool
    DisplayName            string
    State                  SwState
    SubState               volumeSubState
    RefCount               uint
    LastRefCountChangeTime time.Time
    Progress               uint       // 0–100
    TotalSize              int64      // expected size from downloader
    CurrentSize            int64      // current downloaded size
    FileLocation           string
    CreateTime             time.Time
    ContentFormat          zconfig.Format
    LastUse                time.Time
    PreReboot              bool
    ReferenceName          string
    WWN                    string
    Target                 zconfig.Target
    CustomMeta             string
    IsReplicated           bool
    IsNativeContainer      bool
    ErrorAndTimeWithSource
}

func (status VolumeStatus) Key() string
// "<VolumeID>#<GenerationCounter+LocalGenerationCounter>"

func (status VolumeStatus) IsContainer() bool
// ContentFormat == zconfig.Format_CONTAINER

func (status VolumeStatus) PathName() string
// "<VolumeClearDirName or VolumeEncryptedDirName>/<VolumeID>#<gen>.<format>"

func (status VolumeStatus) GetPVCName() string
// "<VolumeID>-pvc-<gen>"  (no '#' — Kubernetes object name compatible)
```

### `VolumesSnapshotConfig` / `VolumesSnapshotStatus`

```go
type VolumesSnapshotConfig struct {
    SnapshotID string
    Action     VolumesSnapshotAction
    VolumeIDs  []uuid.UUID
    AppUUID    uuid.UUID
}
func (config VolumesSnapshotConfig) Key() string  // SnapshotID

type VolumesSnapshotStatus struct {
    SnapshotID         string                 `mandatory:"true"`
    VolumeSnapshotMeta map[string]interface{} `mandatory:"true"`
    TimeCreated        time.Time
    AppUUID            uuid.UUID              `mandatory:"true"`
    RefCount           int
    ResultOfAction     VolumesSnapshotAction
    ErrorAndTimeWithSource
}
func (status VolumesSnapshotStatus) Key() string  // SnapshotID
```

### `ContentTreeConfig` / `ContentTreeStatus` (`contenttreetypes.go`)

```go
type ContentTreeConfig struct {
    ContentID        uuid.UUID
    DatastoreIDList  []uuid.UUID
    RelativeURL      string
    Format           zconfig.Format
    ContentSha256    string
    MaxDownloadSize  uint64
    GenerationCounter int64
    DisplayName      string
    CustomMeta       string
    IsLocal          bool
}
func (config ContentTreeConfig) Key() string  // ContentID.String()

type ContentTreeStatus struct {
    ContentID              uuid.UUID
    DatastoreIDList        []uuid.UUID
    DatastoreTypesList     []zconfig.DatastoreType
    AllDatastoresResolved  bool
    IsOCIRegistry          bool
    RelativeURL            string
    Format                 zconfig.Format
    ContentSha256          string
    MaxDownloadSize        uint64
    GenerationCounter      int64
    DisplayName            string
    HasResolverRef         bool
    State                  SwState
    CreateTime             time.Time
    TotalSize              int64
    CurrentSize            int64
    Progress               uint
    FileLocation           string
    NameIsURL              bool
    Blobs                  []string   // list of blob SHAs
    HVTypeKube             bool
    IsLocal                bool
    ErrorAndTimeWithSource
}

func (status ContentTreeStatus) Key() string  // ContentID.String()
func (status ContentTreeStatus) ReferenceID() string
// Returns RelativeURL, or ContentSha256, or DisplayName
func (status ContentTreeStatus) IsContainer() bool
// Format == zconfig.Format_CONTAINER
func (status ContentTreeStatus) UpdateFromContentTreeConfig(config ContentTreeConfig)
```

---

## 7. Network types — app networking

Defined in `zedroutertypes.go`.

### `AppNetworkConfig`

```go
type AppNetworkConfig struct {
    UUIDandVersion    UUIDandVersion
    DisplayName       string
    Activate          bool
    GetStatsIPAddr    net.IP
    AppNetAdapterList []AppNetAdapterConfig
    CloudInitUserData *string `json:"pubsub-large-CloudInitUserData"`
    CipherBlockStatus CipherBlockStatus
    MetaDataType      MetaDataType
    DeploymentType    AppRuntimeType
}

func (config AppNetworkConfig) Key() string  // UUID.String()
func (config *AppNetworkConfig) IsNetworkUsed(network uuid.UUID) bool
// Returns true if any adapter in AppNetAdapterList references the given NI UUID.
```

### `AppNetworkStatus`

```go
type AppNetworkStatus struct {
    UUIDandVersion       UUIDandVersion
    AppNum               int
    Activated            bool
    PendingAdd           bool
    PendingModify        bool
    PendingDelete        bool
    ConfigInSync         bool
    DisplayName          string
    AppPod               cnirpc.AppPod  // Kubernetes only
    GetStatsIPAddr       net.IP
    DeploymentType       AppRuntimeType
    AppNetAdapterList    []AppNetAdapterStatus
    AwaitNetworkInstance bool
    MACGenerator         int
    ErrorAndTime
}

func (status AppNetworkStatus) Key() string
func (status AppNetworkStatus) Pending() bool
// PendingAdd || PendingModify || PendingDelete

func (status AppNetworkStatus) AwaitingNetwork() bool
// AwaitNetworkInstance

func (status AppNetworkStatus) GetAdaptersStatusForNI(netUUID uuid.UUID) []*AppNetAdapterStatus
// Returns all adapter statuses connected to the given network instance.

func (status AppNetworkStatus) GetAllAppIPs() (appIPs []net.IP)
// Aggregates all IPv4 and IPv6 addresses across all adapters.
```

### `AppNetAdapterConfig`

```go
type AppNetAdapterConfig struct {
    Name          string
    AppMacAddr    net.HardwareAddr
    AppIPAddr     net.IP        // static IP request (optional)
    IntfOrder     int32
    Error         string
    Network       uuid.UUID     // network instance UUID
    ACLs          []ACE
    AccessVlanID  uint32
    IfIdx         uint32
    AllowToDiscover bool
}
```

### `AppNetAdapterStatus`

Embeds `AppNetAdapterConfig` plus runtime state:

```go
type AppNetAdapterStatus struct {
    AppNetAdapterConfig
    VifInfo
    BridgeMac         net.HardwareAddr
    BridgeIPAddr      net.IP
    AssignedAddresses AssignedAddrs
    IPv4Assigned      bool
    IPAddrMisMatch    bool
    HostName          string
}
```

### `AssignedAddrs` / `AssignedAddr` / `AddressSource`

```go
type AddressSource uint8
const (
    AddressSourceUndefined     AddressSource = 0
    AddressSourceEVEInternal   AddressSource = 1 << 0
    AddressSourceInternalDHCP  AddressSource = 1 << 1
    AddressSourceExternalDHCP  AddressSource = 1 << 2
    AddressSourceSLAAC         AddressSource = 1 << 3
    AddressSourceStatic        AddressSource = 1 << 4
)

type AssignedAddr struct {
    Address    net.IP
    AssignedBy AddressSource
}

type AssignedAddrs struct {
    IPv4Addrs []AssignedAddr
    IPv6Addrs []AssignedAddr
}

func (addrs AssignedAddrs) GetInternallyLeasedIPv4Addr() net.IP
// Returns the first IPv4Addr where AssignedBy includes AddressSourceInternalDHCP.
```

### ACL types

```go
type ACEDirection uint8
const (
    AceDirBoth    ACEDirection = 0
    AceDirIngress ACEDirection = 1
    AceDirEgress  ACEDirection = 2
)

type ACEMatch struct {
    Type  string   // "ip", "host", "eidset", "protocol", "fport", "lport", "adapter"
    Value string
}

type ACEAction struct {
    Drop       bool
    Limit      bool
    LimitRate  uint32
    LimitUnit  string
    LimitBurst uint32
    PortMap    bool
    TargetPort int32
}

type ACE struct {
    Matches []ACEMatch
    Actions []ACEAction
    Name    string
    RuleID  int32
    Dir     ACEDirection
}
```

**Note on `ACEMatch.Type == "host"`:** matched as a suffix against the FQDN,
allowing wildcard-style domain matching.

### `NetworkInstanceInfo`

```go
type NetworkInstanceInfo struct {
    BridgeNum    int
    BridgeName   string
    BridgeIPAddr string
    BridgeMac    string
    BridgeIfindex int
    MirrorIfName string
    IPAssignments map[string]AssignedAddrs  // keyed by MAC address string
    Vifs          []VifNameMac
    VlanMap       map[uint32]uint32
    NumTrunkPorts int
}

func (instanceInfo *NetworkInstanceInfo) IsVifInBridge(vifName string) bool
func (instanceInfo *NetworkInstanceInfo) RemoveVif(log *base.LogObject, vifName string)
```

---

## 8. Device port config and network status

### `DevicePortConfig` (`dpc.go`)

Published by NIM (Network Interface Manager).

```go
const (
    LastResortKey = "lastresort"
    ManualDPCKey  = "manual"
    LpsDPCKey     = "lps"
)

const (
    PortCostMin = uint8(0)
    PortCostMax = uint8(255)
    DefaultMTU  = 1500
    MinMTU      = 1280
    MaxMTU      = 65535
)

type DevicePortConfigVersion uint32
const (
    DPCInitial DevicePortConfigVersion = iota
    DPCIsMgmt  // require IsMgmt for management ports
)

type DevicePortConfig struct {
    Version      DevicePortConfigVersion `json:",omitempty"`
    Key          string                  `json:",omitempty"`
    TimePriority time.Time               `json:",omitempty"`
    State        DPCState                `json:",omitempty"`
    TestResults                          // embedded
    LastIPAndDNS time.Time               `json:",omitempty"`
    Ports        []NetworkPortConfig     `json:",omitempty"`
}

func (config DevicePortConfig) PubKey() string
// "<Key>@<TimePriority.UTC().RFC3339Nano>"
// Note: PubKey() is used for pubsub, not Key().
```

### `DeviceNetworkStatus` (`dns.go`)

Published under the fixed key `"global"`. Consumed by all agents that need
to know about network port addresses.

```go
type DeviceNetworkStatus struct {
    DPCKey       string
    Version      DevicePortConfigVersion
    Testing      bool
    State        DPCState
    CurrentIndex int
    RadioSilence RadioSilence
    Ports        []NetworkPortStatus
}

func (status DeviceNetworkStatus) Key() string  // "global"
```

### `NetworkPortStatus` (`dns.go`)

One entry per physical or logical network port.

```go
type NetworkPortStatus struct {
    IfName         string
    Phylabel       string
    Logicallabel   string
    SharedLabels   []string
    Alias          string
    IsMgmt         bool
    IsL3Port       bool
    InvalidConfig  bool
    Cost           uint8
    Dhcp           DhcpType
    Type           NetworkType
    ConfiguredSubnet *net.IPNet
    ConfiguredIP   net.IP
    IgnoredDhcpIPs bool
    IPv4Subnet     *net.IPNet
    IPv6Subnets    []*net.IPNet
    DomainName     string
    DNSServers     []net.IP
    NtpServers     []netutils.HostnameOrIP
    AddrInfoList   []AddrInfo
    ClusterIPAddr  net.IP
    DefaultRouters []net.IP
    Up             bool
    MacAddr        net.HardwareAddr
    MTU            uint16
    WirelessCfg    WirelessConfig
    WirelessStatus WirelessStatus
    PNAC           PNACStatus
    BondStatus     BondStatus
    ConfigSource   PortConfigSource
    ProxyConfig
    L2LinkConfig
    TestResults
    LpsConfigError string
}

func (port NetworkPortStatus) HasIPAndDNS() bool
// true if: has non-link-local unicast addr AND len(DefaultRouters) > 0
//          AND len(DNSServers) > 0
```

### `AddrInfo`

```go
type AddrInfo struct {
    Addr             net.IP
    Geo              ipinfo.IPInfo
    LastGeoTimestamp time.Time
}
```

### `WirelessStatus`

```go
type WirelessStatus struct {
    WType    WirelessType
    Cellular WwanNetworkStatus
}
```

---

## 9. Hardware / IO adapter types

Defined in `assignableadapters.go`, `physicalioadapters.go`, `ifnametopci.go`,
`disktypes.go`, `diskmetrics.go`, `smarttypes.go`.

### `IoAdapter` (`domainmgrtypes.go` / `zedmanagertypes.go`)

```go
type IoAdapter struct {
    Type      IoType
    Name      string
    EthVf     sriov.EthVF
    IntfOrder int32
}
```

### `DiskConfig` / `DiskStatus` (`disktypes.go`)

`DiskStatus` has:

```go
func (status DiskStatus) GetPVCNameFromVolumeKey() string
```

---

## 10. Security types

### Attestation (`attesttypes.go`)

```go
type AttestState uint8
const (
    StateNone                AttestState = iota
    StateNonceWait
    StateInternalQuoteWait
    StateInternalEscrowWait
    StateAttestWait
    StateAttestEscrowWait
    StateRestartWait
    StateComplete
    StateAny                 // used as wildcard in state machine
)

func (state AttestState) String() string  // uncovered — good unit test target
```

```go
type AttestNonce struct {
    Nonce     []byte
    Requester string
}
func (nonce AttestNonce) Key() string  // hex.EncodeToString(Nonce)

type PCRValue struct {
    Index  uint32
    Algo   PCRExtendHashType
    Digest []byte
}

type AttestQuote struct {
    Nonce     []byte
    SigType   SigAlg
    Signature []byte
    Quote     []byte
    PCRs      []PCRValue
}
func (quote AttestQuote) Key() string  // hex.EncodeToString(Nonce)

type EdgeNodeCert struct {
    HashAlgo      CertHashType
    CertID        []byte
    CertType      CertType
    Cert          []byte  // PEM encoded
    IsTpm         bool
    MetaDataItems []*MetaDataItem
}
func (cert EdgeNodeCert) Key() string  // hex.EncodeToString(CertID)
```

### Cipher types (`cipherinfotypes.go`)

`CipherBlockStatus` is embedded in config types that carry encrypted fields
(e.g., `AppInstanceConfig`, `AppNetworkConfig`, `DomainConfig`).

```go
type CipherBlockStatus struct {
    CipherBlockID   string
    CipherContextID string
    InitialValue    []byte
    CipherData      []byte
    ClearTextHash   []byte
    IsCipher        bool
    CipherContext   *CipherContext
}
```

---

## 11. Global configuration types

Defined in `global.go`.

### `ConfigItemType`

```go
type ConfigItemType uint8
const (
    ConfigItemTypeInvalid  ConfigItemType = iota
    ConfigItemTypeInt
    ConfigItemTypeBool
    ConfigItemTypeString
    ConfigItemTypeTriState
)
```

### `ConfigItemValue`

```go
type ConfigItemValue struct {
    Key          GlobalSettingKey
    ItemType     ConfigItemType
    IntValue     uint32
    StrValue     string
    BoolValue    bool
    TriStateValue TriState
}

func (val ConfigItemValue) StringValue() string
// Converts the value to string based on ItemType:
//   Int → strconv.FormatUint
//   Bool → strconv.FormatBool
//   TriState → FormatTriState
//   String → StrValue
```

### `ConfigItemValueMap`

The current in-memory global configuration, published by `baseosmgr` /
read by all agents.

```go
type ConfigItemValueMap struct {
    GlobalSettings map[GlobalSettingKey]ConfigItemValue
    AgentSettings  map[string]map[AgentSettingKey]ConfigItemValue
}

func NewConfigItemValueMap() *ConfigItemValueMap

// Global setting getters:
func (configPtr *ConfigItemValueMap) GlobalValueInt(key GlobalSettingKey) uint32
func (configPtr *ConfigItemValueMap) GlobalValueString(key GlobalSettingKey) string
func (configPtr *ConfigItemValueMap) GlobalValueTriState(key GlobalSettingKey) TriState
func (configPtr *ConfigItemValueMap) GlobalValueBool(key GlobalSettingKey) bool

// Global setting setters:
func (configPtr *ConfigItemValueMap) SetGlobalValueInt(key GlobalSettingKey, value uint32)
func (configPtr *ConfigItemValueMap) SetGlobalValueBool(key GlobalSettingKey, value bool)
func (configPtr *ConfigItemValueMap) SetGlobalValueTriState(key GlobalSettingKey, value TriState)
func (configPtr *ConfigItemValueMap) SetGlobalValueString(key GlobalSettingKey, value string)

// Per-agent setting getters:
func (configPtr *ConfigItemValueMap) AgentSettingStringValue(agentName string, key AgentSettingKey) string

// Per-agent setting setters:
func (configPtr *ConfigItemValueMap) SetAgentSettingStringValue(agentName string, itemKey AgentSettingKey, newValue string)
func (configPtr *ConfigItemValueMap) DelAgentValue(itemKey AgentSettingKey, agentName string)

func (configPtr *ConfigItemValueMap) AgentSettingValue(agentName string, key AgentSettingKey) (ConfigItemValue, bool)

// Merge: dst.AgentSettings = src if provided
func (configPtr *ConfigItemValueMap) UpdateItemValuesFromGlobalConfig(gc ConfigItemValueMap)
```

### `ConfigItemSpec`

Defines the allowed range and default for a single config item.

```go
type ConfigItemSpec struct {
    Key              string
    ItemType         ConfigItemType
    IntMin           uint32
    IntMax           uint32
    IntDefault       uint32
    StringValidator  func(string) error
    StringDefault    string
    BoolDefault      bool
    TriStateDefault  TriState
}

func (spec ConfigItemSpec) DefaultValue() ConfigItemValue
```

### `ConfigItemSpecMap`

Registry of all known config items (both global and per-agent).

```go
type ConfigItemSpecMap struct {
    GlobalSettings map[GlobalSettingKey]ConfigItemSpec
    AgentSettings  map[AgentSettingKey]ConfigItemSpec
}

func NewConfigItemSpecMap() ConfigItemSpecMap

func (specMap *ConfigItemSpecMap) AddIntItem(key GlobalSettingKey, defaultInt uint32, min, max uint32)
func (specMap *ConfigItemSpecMap) AddBoolItem(key GlobalSettingKey, defaultBool bool)
func (specMap *ConfigItemSpecMap) AddStringItem(key GlobalSettingKey, defaultStr string, validator func(string) error)
func (specMap *ConfigItemSpecMap) AddTriStateItem(key GlobalSettingKey, defaultTriState TriState)
func (specMap *ConfigItemSpecMap) ParseItem(log *base.LogObject, globalConfig *ConfigItemValueMap,
    keyStr string, valueStr string) ConfigItemStatus
```

### `GlobalStatus`

Reflects the current config items back to the controller.

```go
type GlobalStatus struct {
    ConfigItems        map[string]ConfigItemStatus
    UnknownConfigItems map[string]ConfigItemStatus
}

func NewGlobalStatus() *GlobalStatus
func (gs *GlobalStatus) UpdateItemValuesFromGlobalConfig(gc ConfigItemValueMap)
// private: setItemValue, setItemValueInt, setItemValueTriState, setItemValueBool
```

### Key `GlobalSettingKey` constants (selected)

**Timer keys:**

```text
ConfigInterval, CertInterval, MetricInterval, HardwareHealthInterval,
DevInfoInterval, DiskScanMetricInterval, ResetIfCloudGoneTime,
FallbackIfCloudGoneTime, MintimeUpdateSuccess, VdiskGCTime,
DeferContentDelete, DownloadRetryTime, DownloadStalledTime,
DomainBootRetryTime, NetworkGeoRedoTime, NetworkGeoRetryTime,
NetworkTestDuration, NetworkTestInterval, NetworkTestBetterInterval,
NetworkTestTimeout, NetworkSendTimeout, NetworkDialTimeout,
LocationCloudInterval, LocationAppInterval, NTPSourcesInterval,
AppContainerStatsInterval, VaultReadyCutOffTime
```

**Storage keys:**

```text
Dom0MinDiskUsagePercent, Dom0DiskUsageMaxBytes, StorageZfsReserved,
LonghornDiskReservedGB, LogRemainToSendMBytes
```

**Bool keys:**

```text
UsbAccess, VgaAccess, AllowAppVnc, NetworkFallbackAnyEth,
SSHAuthorizedKeys (actually string), VectorEnabled, etc.
```

**Network:**

```text
DownloadMaxPortCost, BlobDownloadMaxRetries
```

**Cluster/K8s:**

```text
KubernetesDrainTimeout, K3sConfigOverride, K3sVersionOverride
```

### `AgentSettingKey`

```go
type AgentSettingKey string
const (
    LogLevel       AgentSettingKey = "debug.loglevel"
    RemoteLogLevel AgentSettingKey = "debug.remote.loglevel"
)
```

### Time constants

```go
const (
    MinuteInSec = 60
    HourInSec   = 60 * MinuteInSec
)
```

---

## 12. Download, verify, and blob types

### `DownloaderConfig` / `DownloaderStatus` (`downloadertypes.go`)

```go
type DownloaderConfig struct {
    ImageSha256     string
    DatastoreIDList []uuid.UUID
    Name            string
    Target          zconfig.Target
    NameIsURL       bool
    Size            uint64
    FinalObjDir     string
    RefCount        uint
    LastRetry       time.Time
}
func (config DownloaderConfig) Key() string  // ImageSha256

type DownloaderStatus struct {
    ImageSha256     string
    DatastoreIDList []uuid.UUID
    Target          zconfig.Target
    Name            string
    RefCount        uint
    LastUse         time.Time
    Expired         bool
    NameIsURL       bool
    State           SwState
    ReservedSpace   uint64
    Size            uint64
    TotalSize       int64
    CurrentSize     int64
    Progress        uint
    ModTime         time.Time
    ContentType     string
    ErrorAndTime
}
func (status DownloaderStatus) Key() string  // ImageSha256
func (status *DownloaderStatus) HandleDownloadFail(log *base.LogObject, errStr string, retry bool)
```

### `VerifyImageConfig` / `VerifyImageStatus` (`verifiertypes.go`)

```go
type VerifyImageConfig struct {
    ImageSha256  string
    Name         string
    MediaType    string
    FileLocation string
    Size         int64
    RefCount     uint
    Expired      bool
}
func (config VerifyImageConfig) Key() string  // ImageSha256

type VerifyImageStatus struct {
    ImageSha256   string
    Name          string
    FileLocation  string
    Size          int64
    MediaType     string
    PendingAdd    bool
    PendingModify bool
    PendingDelete bool
    State         SwState
    ErrorAndTime
}
func (status VerifyImageStatus) Key() string  // ImageSha256
func (status VerifyImageStatus) Pending() bool
// PendingAdd || PendingModify || PendingDelete
```

### Blob types (`blob.go`)

`BlobStatus` tracks an individual OCI layer blob (identified by content hash).
It embeds `ErrorAndTime`.

---

## 13. Cluster and Kubernetes types

Defined in `clustertypes.go`, `clusterupdatetypes.go`, `zedkubetypes.go`.

These types support the kubevirt/k3s deployment mode (`HVTypeKube`).

### Key helpers (`base/kubevirt.go`)

```go
func IsHVTypeKube(hvType string) bool
func IsVersionHVTypeKube(version string) bool
```

### `ZedKubeConfig` / `ZedKubeStatus` (`zedkubetypes.go`)

Published by `zedkube` agent. `ZedKubeConfig` is published under key `"global"`.

---

## 14. Metrics and monitoring types

### `ZedCloudMetrics` (`zedcloudmetrics.go`)

Tracks per-URL send statistics for controller communication.

### `FlowLogMetrics` (`flowlogmetrics.go`)

Tracks network flow log ingestion statistics.

### `DiskMetrics` (`diskmetrics.go`)

Disk usage and I/O performance per filesystem.

### `SmartInfo` / `SmartAttr` (`smarttypes.go`)

SMART health data for storage devices.

### `MemoryStatus` (`memory.go`)

System and EVE process memory usage.

---

## 15. Utility and infrastructure types

### `UEvent` (`types.go`)

Kernel uevent notification.

```go
type UEvent struct {
    Action string
    Obj    string
    Env    map[string]string
}
```

### `TestResults` (`dpc.go`)

Embedded in `DevicePortConfig`, `NetworkPortStatus`, etc.

```go
type TestResults struct {
    LastFailed    time.Time
    LastSucceeded time.Time
    LastError     string
    LastWarning   string
}
func (tr *TestResults) RecordSuccess()
func (tr *TestResults) RecordFailure(errStr string)
func (tr *TestResults) RecordWarning(warnStr string)
func (tr *TestResults) HasError() bool
func (tr TestResults) LastFail() time.Time
func (tr TestResults) LastSucceed() time.Time
```

### Constants in `volumetypes.go`

```go
const (
    VolumeClearDirName     = "/persist/vault/volumes"
    VolumeEncryptedDirName = "/persist/vault/volumes"  // same dir, different handling
    // (exact constants defined in file — check for current values)
)
```

### `RadioSilence` (`dns.go`)

Controls whether wireless radios are silenced (used by `DeviceNetworkStatus`).

### `PNACStatus` (`pnac.go`)

Port Network Access Control state (802.1x).

### `BondStatus` (`bond.go`)

Aggregation state for bonded (LAG) interfaces.

### `LocationConsts` (`locationconsts.go`)

Geographic location constants used for location reporting.

### `ScepConfig` (`scep.go`)

SCEP certificate enrollment configuration.

### Exec / Process types (`exectypes.go`, `processtypes.go`)

Used to pass commands between `zedagent` and `executor` agent.

---

## 16. Standalone functions

```go
// types.go
func UuidsToStrings(uuids []uuid.UUID) []string

// types.go
func ParseTriState(value string) (TriState, error)
func FormatTriState(state TriState) string

// errortime.go
func GetErrorSeverity(retryCount int, timeSpend time.Duration) ErrorSeverity

// global.go
func NewGlobalStatus() *GlobalStatus
func NewConfigItemValueMap() *ConfigItemValueMap
func NewConfigItemSpecMap() ConfigItemSpecMap

// errors.go — sentinel error constructors (via struct literal, no constructor)
// type IPAddrNotAvailError, DNSNotAvailError
```

---

## 17. Testing guide

### What to test and how

#### Enum `String()` and conversion methods

Every enum type has a `String()` method. Test all values including the
default/zero case and any out-of-range value:

```go
func TestSwStateString(t *testing.T) {
    cases := []struct{ state SwState; want string }{
        {INITIAL, "INITIAL"},
        {RUNNING, "RUNNING"},
        {FAILED, "FAILED"},
        {SwState(0), "Unknown state 0"},   // below the iota+100 range
    }
    ...
}
```

Similarly test `SwState.ZSwState()` for every case, paying attention to the
non-obvious mappings (PAUSING→RUNNING, PAUSED→INSTALLED, BROKEN→HALTING).

#### `TriState` parse / format round-trip

```go
for _, s := range []string{"none", "enabled", "enable", "on",
                            "disabled", "disable", "off"} {
    ts, err := ParseTriState(s)
    require.NoError(t, err)
    // FormatTriState(ts) may differ from s (e.g., "on" → "enabled")
}
// error case:
_, err := ParseTriState("bogus")
require.Error(t, err)
```

#### `Key()` methods

Every type that implements `Key()` should be tested with:

1. Normal values — verify format.
2. Zero-value UUID — should produce the nil UUID string, not panic.
3. Composite keys (VolumeConfig, VolumeStatus) — verify
   `GenerationCounter + LocalGenerationCounter` arithmetic is correct,
   including counter overflow behavior at `math.MaxInt64`.

#### `ErrorAndTime` / `ErrorAndTimeWithSource`

```go
var et ErrorAndTime
assert.False(t, et.HasError())

et.SetErrorNow("something went wrong")
assert.True(t, et.HasError())
assert.False(t, et.ErrorTime.IsZero())
assert.Equal(t, ErrorSeverityError, et.ErrorSeverity)

et.ClearError()
assert.False(t, et.HasError())
assert.Equal(t, ErrorSeverityUnspecified, et.ErrorSeverity)
```

For `ErrorAndTimeWithSource`, test `IsErrorSource` type matching:

```go
type FakeSourceA struct{}
type FakeSourceB struct{}

var ets ErrorAndTimeWithSource
ets.SetErrorWithSource("err", FakeSourceA{}, time.Now())
assert.True(t, ets.IsErrorSource(FakeSourceA{}))
assert.False(t, ets.IsErrorSource(FakeSourceB{}))

// Pointer should panic:
assert.Panics(t, func() { ets.IsErrorSource(&FakeSourceA{}) })
```

#### `ErrorDescription.ToProto()`

```go
ed := ErrorDescription{}
assert.Nil(t, ed.ToProto())  // zero ErrorTime → nil

ed.SetErrorDescription(ErrorDescription{Error: "fail"})
proto := ed.ToProto()
require.NotNil(t, proto)
assert.Equal(t, "fail", proto.Description)
assert.Equal(t, info.Severity_SEVERITY_ERROR, proto.Severity)
```

#### `GetErrorSeverity`

```go
assert.Equal(t, ErrorSeverityNotice,  GetErrorSeverity(0, 0))
assert.Equal(t, ErrorSeverityNotice,  GetErrorSeverity(9, 59*time.Minute))
assert.Equal(t, ErrorSeverityWarning, GetErrorSeverity(10, 0))
assert.Equal(t, ErrorSeverityWarning, GetErrorSeverity(0, time.Hour))
assert.Equal(t, ErrorSeverityError,   GetErrorSeverity(20, 0))
assert.Equal(t, ErrorSeverityError,   GetErrorSeverity(0, 10*time.Hour))
```

#### `VolumeStatus` method tests

```go
s := VolumeStatus{ContentFormat: zconfig.Format_CONTAINER}
assert.True(t, s.IsContainer())

s.ContentFormat = zconfig.Format_RAW
assert.False(t, s.IsContainer())

s.VolumeID = uuid.NewV4()
s.GenerationCounter = 3
s.LocalGenerationCounter = 1
assert.Equal(t, fmt.Sprintf("%s#4", s.VolumeID), s.Key())
assert.Contains(t, s.GetPVCName(), "pvc-4")
assert.NotContains(t, s.GetPVCName(), "#")  // Kubernetes safety
```

#### `DPCState` method tests

```go
for _, in := range []DPCState{
    DPCStateIPDNSWait, DPCStatePCIWait,
    DPCStateIntfWait, DPCStateAsyncWait, DPCStateWwanWait,
} {
    assert.True(t, in.InProgress(), in.String())
}
for _, s := range []DPCState{
    DPCStateNone, DPCStateFail, DPCStateFailWithIPAndDNS,
    DPCStateSuccess, DPCStateRemoteWait,
} {
    assert.False(t, s.InProgress(), s.String())
}
```

#### `AppNetworkStatus` method tests

```go
ni1 := uuid.NewV4()
ni2 := uuid.NewV4()
status := AppNetworkStatus{
    AppNetAdapterList: []AppNetAdapterStatus{
        {AppNetAdapterConfig: AppNetAdapterConfig{Network: ni1},
         AssignedAddresses: AssignedAddrs{
             IPv4Addrs: []AssignedAddr{{Address: net.ParseIP("10.0.0.2")}},
         }},
        {AppNetAdapterConfig: AppNetAdapterConfig{Network: ni2}},
    },
}
adapters := status.GetAdaptersStatusForNI(ni1)
assert.Len(t, adapters, 1)

ips := status.GetAllAppIPs()
assert.Len(t, ips, 1)
assert.Equal(t, net.ParseIP("10.0.0.2"), ips[0])

status.PendingAdd = true
assert.True(t, status.Pending())
status.PendingAdd = false
assert.False(t, status.Pending())
```

#### `NetworkPortStatus.HasIPAndDNS()` tests

```go
port := NetworkPortStatus{}
assert.False(t, port.HasIPAndDNS())  // no addrs

port.AddrInfoList = []AddrInfo{{Addr: net.ParseIP("192.168.1.5")}}
port.DefaultRouters = []net.IP{net.ParseIP("192.168.1.1")}
port.DNSServers = []net.IP{net.ParseIP("8.8.8.8")}
assert.True(t, port.HasIPAndDNS())

// Link-local only → false
port.AddrInfoList = []AddrInfo{{Addr: net.ParseIP("fe80::1")}}
assert.False(t, port.HasIPAndDNS())
```

#### `ConfigItemValueMap` tests

```go
m := NewConfigItemValueMap()
m.SetGlobalValueInt(ConfigInterval, 60)
assert.Equal(t, uint32(60), m.GlobalValueInt(ConfigInterval))

m.SetGlobalValueBool(UsbAccess, true)
assert.True(t, m.GlobalValueBool(UsbAccess))

m.SetGlobalValueTriState(NetworkFallbackAnyEth, TS_ENABLED)
assert.Equal(t, TS_ENABLED, m.GlobalValueTriState(NetworkFallbackAnyEth))

m.SetAgentSettingStringValue("nim", LogLevel, "debug")
assert.Equal(t, "debug", m.AgentSettingStringValue("nim", LogLevel))
```

#### `UuidToNum` / `AppInterfaceToNum` (objtonum contract)

```go
key := UuidToNumKey{UUID: uuid.NewV4()}
var proto UuidToNum
container := proto.New(key)
n := container.(*UuidToNum)

n.SetNumber(42, "appNum")
num, typ := n.GetNumber()
assert.Equal(t, 42, num)
assert.Equal(t, "appNum", typ)

n.SetReservedOnly(true)
assert.True(t, n.IsReservedOnly())
n.SetReservedOnly(false)
assert.False(t, n.IsReservedOnly())

k := n.GetKey()
assert.Equal(t, key, k)
```

#### Sentinel errors

```go
err := &IPAddrNotAvailError{IfName: "eth0"}
assert.Contains(t, err.Error(), "eth0")
assert.Contains(t, err.Error(), "no suitable IP address")

err2 := &DNSNotAvailError{IfName: "wlan0"}
assert.Contains(t, err2.Error(), "wlan0")
assert.Contains(t, err2.Error(), "no DNS server")
```

### Files with the most uncovered functions (prioritized)

| File | Uncovered fns | Notes |
|------|--------------|-------|
| `zedroutertypes.go` | 60 | NI config, VIF, VLAN, ACL methods |
| `dpc.go` | 41 | DPC log methods, TestResults |
| `wwan.go` | 37 | WWAN status String() methods |
| `dns.go` | 35 | DNS types, HasIPAndDNS, port methods |
| `volumetypes.go` | 34 | IsContainer, PathName, GetPVCName |
| `global.go` | 26 | ConfigItemValueMap getters/setters |
| `assignableadapters.go` | 25 | PCI/IO adapter lookups |
| `zedagenttypes.go` | 23 | ZedAgent config/status types |
| `types.go` | 23 | SwState.ZSwState, UuidToNum methods |
| `domainmgrtypes.go` | 21 | DomainConfig, VmMode, DiskConfig |
| `errortime.go` | 11 | GetErrorSeverity, ClearError variants |
| `contenttreetypes.go` | 11 | ReferenceID, IsContainer, Update |
| `conntest.go` | 11 | Connectivity test result types |
| `cipherinfotypes.go` | 11 | Cipher block status methods |
| `attesttypes.go` | 12 | AttestState.String, Key methods |
| `patchenvelopestypes.go` | 14 | PatchEnvelope status methods |
| `evaluation.go` | 9+ | Configuration evaluation types |

### Packages to import in test files

```go
import (
    "fmt"
    "net"
    "testing"
    "time"

    "github.com/lf-edge/eve/pkg/pillar/types"
    zconfig "github.com/lf-edge/eve-api/go/config"
    "github.com/lf-edge/eve-api/go/info"
    uuid "github.com/satori/go.uuid"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)
```

Tests that call `LogCreate` / `LogModify` / `LogDelete` need a
`*base.LogObject`. Use `base.NewSourceLogObject(logrus.StandardLogger(), "test", 0)`
or simply avoid exercising those paths in coverage-focused tests (the pubsub
framework itself is tested elsewhere).
