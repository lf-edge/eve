// Copyright (c) 2019,2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import "strings"

const (
	// TmpDirname - used for files fed into pubsub as global subscriptions
	TmpDirname = "/run/global"

	// PersistDir - Location to store persistent files.
	PersistDir = "/persist"
	// PersistConfigDir is where we keep some configuration across reboots
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
	// EveMemoryLimitFile - stores memory reserved for eve
	EveMemoryLimitFile = "/hostfs/sys/fs/cgroup/memory/eve/memory.soft_limit_in_bytes"
	// EveMemoryUsageFile - current usage
	EveMemoryUsageFile = "/hostfs/sys/fs/cgroup/memory/eve/memory.usage_in_bytes"
	// EveKmemUsageFile - current kernel usage
	EveKmemUsageFile = "/hostfs/sys/fs/cgroup/memory/eve/memory.kmem.usage_in_bytes"
	// ZFSArcMaxSizeFile - file with zfs_arc_max size in bytes
	ZFSArcMaxSizeFile = "/hostfs/sys/module/zfs/parameters/zfs_arc_max"

	// ContainerdContentDir - path to containerd`s content store
	ContainerdContentDir = SealedDirName + "/containerd/io.containerd.content.v1.content"
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
)
