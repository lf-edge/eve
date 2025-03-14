// Copyright (c) 2019,2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import "strings"

const (
	// TmpDirname - used for files fed into pubsub as global subscriptions
	TmpDirname = "/run/global"

	// PersistDir - Location to store persistent files.
	PersistDir = "/persist"
	// PersistConfigDir is where we used to keep some configuration across reboots. Remove once upgradeconverter code is removed.
	PersistConfigDir = PersistDir + "/config"
	// PersistStatusDir is where we keep some configuration across reboots
	PersistStatusDir = PersistDir + "/status"
	// CertificateDirname - Location of certificates
	CertificateDirname = PersistDir + "/certs"
	// SealedDirName - directory sealed under TPM PCRs
	SealedDirName = PersistDir + "/vault"
	// VolumeEncryptedDirName - sealed directory used to store volumes
	VolumeEncryptedDirName = SealedDirName + "/volumes"
	// ClearDirName - directory which is not encrypted
	ClearDirName = PersistDir + "/clear"
	// VolumeClearDirName - Not encrypted directory used to store volumes
	VolumeClearDirName = ClearDirName + "/volumes"
	// PersistDebugDir - Location for service specific debug/traces
	PersistDebugDir = PersistDir + "/agentdebug"
	// PersistInstallerDir - location for installer output
	PersistInstallerDir = PersistDir + "/installer"
	// IngestedDirname - location for shas of files we pulled from /config
	IngestedDirname = PersistDir + "/ingested"
	// SnapshotsDirname - location for snapshots
	SnapshotsDirname = PersistDir + "/snapshots"
	// SnapshotAppInstanceConfigFilename - file to store snapshot-related app instance config
	SnapshotAppInstanceConfigFilename = "appInstanceConfig.json"
	// SnapshotVolumesSnapshotStatusFilename - file to store volume snapshot status
	SnapshotVolumesSnapshotStatusFilename = "volumesSnapshotStatus.json"
	// SnapshotInstanceStatusFilename - file to store SnapshotInstanceStatus
	SnapshotInstanceStatusFilename = "snapshotInstanceStatus.json"
	// PersistCachePatchEnvelopes - folder to store inline patch envelopes
	PersistCachePatchEnvelopes = PersistDir + "/patchEnvelopesCache"
	// PersistCachePatchEnvelopesUsage - folder to store patch envelopes usage stat per app
	PersistCachePatchEnvelopesUsage = PersistDir + "/patchEnvelopesUsageCache"

	// IdentityDirname - Config dir
	IdentityDirname = "/config"
	// ServerFileName - server file
	ServerFileName = IdentityDirname + "/server"
	// DeviceCertName - device certificate
	DeviceCertName = IdentityDirname + "/device.cert.pem"
	// DeviceKeyName - device private key (if not in TPM)
	DeviceKeyName = IdentityDirname + "/device.key.pem"
	// OnboardCertName - Onboard certificate
	OnboardCertName = IdentityDirname + "/onboard.cert.pem"
	// OnboardKeyName - onboard key
	OnboardKeyName = IdentityDirname + "/onboard.key.pem"
	// RootCertFileName - what we trust for signatures and object encryption
	RootCertFileName = IdentityDirname + "/root-certificate.pem"
	// V2TLSCertShaFilename - find TLS root cert for API V2 based on this sha
	V2TLSCertShaFilename = CertificateDirname + "/v2tlsbaseroot-certificates.sha256"
	// V2TLSBaseFile is where the initial file
	V2TLSBaseFile = IdentityDirname + "/v2tlsbaseroot-certificates.pem"
	// APIV1FileName - user can statically allow for API v1
	APIV1FileName = IdentityDirname + "/Force-API-V1"
	// BootstrapConfFileName - file to store initial device configuration for bootstrapping
	BootstrapConfFileName = IdentityDirname + "/bootstrap-config.pb"
	// RemoteAccessFlagFileName -- file to check for remote access configuration
	RemoteAccessFlagFileName = IdentityDirname + "/remote_access_disabled"
	// BootstrapShaFileName - file to store SHA hash of an already ingested bootstrap config
	BootstrapShaFileName = IngestedDirname + "/bootstrap-config.sha"

	// ServerSigningCertFileName - filename for server signing leaf certificate
	ServerSigningCertFileName = CertificateDirname + "/server-signing-cert.pem"

	// ShareCertDirname - directory to place private proxy server certificates
	ShareCertDirname = "/usr/local/share/ca-certificates"

	// AppImgObj - name of app image type
	AppImgObj = "appImg.obj"
	// BaseOsObj - name of base image type
	BaseOsObj = "baseOs.obj"
	//ITokenFile contains the integrity token sent in attestation response
	ITokenFile = "/run/eve.integrity_token"
	//EveVersionFile contains the running version of EVE
	EveVersionFile = "/run/eve-release"
	//DefaultVaultName is the name of the default vault
	DefaultVaultName = "Application Data Store"

	// NewlogDir - newlog directories
	NewlogDir = "/persist/newlog"
	// NewlogCollectDir - newlog collect directory for temp log files
	NewlogCollectDir = NewlogDir + "/collect"
	// NewlogUploadDevDir - newlog device gzip file directory ready for upload
	NewlogUploadDevDir = NewlogDir + "/devUpload"
	// NewlogUploadAppDir - newlog app gzip file directory ready for upload
	NewlogUploadAppDir = NewlogDir + "/appUpload"
	// NewlogKeepSentQueueDir - a circular queue of gzip files already been sent
	NewlogKeepSentQueueDir = NewlogDir + "/keepSentQueue"
	// PillarHardMemoryLimitFile - hard memory reserved for pillar
	PillarHardMemoryLimitFile = "/hostfs/sys/fs/cgroup/memory/eve/services/pillar/memory.limit_in_bytes"
	// EveMemoryLimitFile - stores memory reserved for eve
	EveMemoryLimitFile = "/hostfs/sys/fs/cgroup/memory/eve/memory.limit_in_bytes"
	// EveMemoryUsageFile - current usage
	EveMemoryUsageFile = "/hostfs/sys/fs/cgroup/memory/eve/memory.usage_in_bytes"
	// EveKmemUsageFile - current kernel usage
	EveKmemUsageFile = "/hostfs/sys/fs/cgroup/memory/eve/memory.kmem.usage_in_bytes"
	// ZFSArcMaxSizeFile - file with zfs_arc_max size in bytes
	ZFSArcMaxSizeFile = "/hostfs/sys/module/zfs/parameters/zfs_arc_max"

	// DownloaderDir - storage for downloader
	DownloaderDir = SealedDirName + "/downloader"

	// VerifierDir - storage for verifier
	VerifierDir = SealedDirName + "/verifier"

	// ContainerdDir - path to user containerd storage
	ContainerdDir = SealedDirName + "/containerd"

	// ContainerdContentDir - path to containerd`s content store
	ContainerdContentDir = ContainerdDir + "/io.containerd.content.v1.content"

	// VtpmdCtrlSocket is UDS to ask vtpmd to launch SWTP instances for VMs
	VtpmdCtrlSocket = "/run/swtpm/vtpmd.ctrl.sock"
	// SwtpmCtrlSocketPath SWTPM per-vm socket path, the format string is filled with the App UUID
	SwtpmCtrlSocketPath = "/run/swtpm/%s.ctrl.sock"
	// SwtpmPidPath is SWTPM per-vm pid file path, the format string is filled with the App UUID
	SwtpmPidPath = "/run/swtpm/%s.pid"

	// MemoryMonitorDir - directory for memory monitor
	MemoryMonitorDir = PersistDir + "/memory-monitor"
	// MemoryMonitorOutputDir - directory for memory monitor output
	MemoryMonitorOutputDir = MemoryMonitorDir + "/output"
	// MemoryMonitorPSIStatsFile - file to store memory PSI (Pressure Stall Information) statistics
	MemoryMonitorPSIStatsFile = MemoryMonitorOutputDir + "/psi.txt"

	// OVMFSettingsDir - directory for OVMF settings, they are stored in per-domain files
	OVMFSettingsDir = SealedDirName + "/ovmf"
	// OVMFSettingsTemplate - template file for OVMF settings
	OVMFSettingsTemplate = "/usr/lib/xen/boot/OVMF_VARS.fd"
	// CustomOVMFSettingsDir - directory for custom OVMF settings (for different resolutions)
	CustomOVMFSettingsDir = "/hostfs/etc/ovmf"
)

var (
	// PersistDataset - parent dataset
	PersistDataset = strings.TrimLeft(PersistDir, "/")
	// PersistPool - parent pool
	PersistPool = PersistDataset
	// ClearDataset - dataset which is not encrypted
	ClearDataset = strings.TrimLeft(ClearDirName, "/")
	// SealedDataset - dataset sealed under TPM PCRs
	SealedDataset = strings.TrimLeft(SealedDirName, "/")
	// PersistReservedDataset - reserved dataset
	PersistReservedDataset = PersistDataset + "/reserved"
	//VolumeClearZFSDataset - dataset to create volumes without encryption
	VolumeClearZFSDataset = ClearDataset + "/volumes"
	//VolumeEncryptedZFSDataset - dataset to create volumes with encryption
	VolumeEncryptedZFSDataset = SealedDataset + "/volumes"
	// EtcdZvol - zvol encrypted for etcd storage
	EtcdZvol = PersistDataset + "/etcd-storage"
)
