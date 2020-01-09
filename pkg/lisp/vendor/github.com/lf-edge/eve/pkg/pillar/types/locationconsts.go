// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

const (
	// TmpDirname - temporary dir. for agents to use.
	TmpDirname = "/var/tmp/zededa"

	// PersistDir - Location to store persistent files.
	PersistDir = "/persist"
	// PersistConfigDir is where we keep some configuration across reboots
	PersistConfigDir = PersistDir + "/config"
	// PersistStatusDir is where we keep some configuration across reboots
	PersistStatusDir = PersistDir + "/status"
	// DownloadDirname - Location of downloaded images / objects
	DownloadDirname = PersistDir + "/downloads"
	// CertificateDirname - Location of certificates
	CertificateDirname = PersistDir + "/certs"
	// AppImgDirname - location of downloaded app images. Read-only images
	// named based on sha256 hash each in its own directory
	AppImgDirname = DownloadDirname + "/" + AppImgObj
	// VerifiedAppImgDirname - Location of verified App images. Read-only images
	// named based on sha256 hash each in its own directory
	VerifiedAppImgDirname = AppImgDirname + "/verified"

	// IdentityDirname - Config dir
	IdentityDirname = "/config"
	// SelfRegFile - name of self-register-filed file
	SelfRegFile = IdentityDirname + "/self-register-failed"
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
	// UUIDFileName - device UUID
	UUIDFileName = IdentityDirname + "/uuid"

	// APIV2FileName - user can statically allow for API v2
	APIV2FileName = IdentityDirname + "/Force-API-V2"
	// ServerSigningCertFileName - filename for server signing leaf certificate
	ServerSigningCertFileName = CertificateDirname + "/server-signing-cert.pem"

	// AppImgObj - name of app image obj dir
	AppImgObj = "appImg.obj"
	// BaseOsObj - name of base image obj dir
	BaseOsObj = "baseOs.obj"
	// CertObj - Name of Certificate obj. dir
	CertObj = "cert.obj"
)
