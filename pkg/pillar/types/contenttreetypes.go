// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"errors"
	"fmt"
	"os"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// ContentTreeConfig specifies the needed information for content tree
// which might need to be downloaded and verified
type ContentTreeConfig struct {
	ContentID         uuid.UUID
	DatastoreID       uuid.UUID
	RelativeURL       string
	Format            zconfig.Format
	ContentSha256     string
	MaxDownloadSize   uint64
	GenerationCounter int64
	ImageSignature    []byte   //signature of image
	SignatureKey      string   //certificate containing public key
	CertificateChain  []string //name of intermediate certificates
	DisplayName       string
}

// Key is content info UUID which will be unique
func (config ContentTreeConfig) Key() string {
	return config.ContentID.String()
}

// LogCreate :
func (config ContentTreeConfig) LogCreate() {
	logObject := base.NewLogObject(base.ContentTreeConfigLogType, config.DisplayName,
		config.ContentID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("datastore-id", config.DatastoreID).
		AddField("relative-URL", config.RelativeURL).
		AddField("format", config.Format).
		AddField("content-sha256", config.ContentSha256).
		AddField("max-download-size-int64", config.MaxDownloadSize).
		Infof("Content tree config create")
}

// LogModify :
func (config ContentTreeConfig) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(base.ContentTreeConfigLogType, config.DisplayName,
		config.ContentID, config.LogKey())

	oldConfig, ok := old.(ContentTreeConfig)
	if !ok {
		log.Errorf("LogModify: Old object interface passed is not of ContentTreeConfig type")
	}
	if oldConfig.DatastoreID != config.DatastoreID ||
		oldConfig.RelativeURL != config.RelativeURL ||
		oldConfig.Format != config.Format ||
		oldConfig.ContentSha256 != config.ContentSha256 ||
		oldConfig.MaxDownloadSize != config.MaxDownloadSize {

		logObject.CloneAndAddField("datastore-id", config.DatastoreID).
			AddField("relative-URL", config.RelativeURL).
			AddField("format", config.Format).
			AddField("content-sha256", config.ContentSha256).
			AddField("max-download-size-int64", config.MaxDownloadSize).
			AddField("old-datastore-id", oldConfig.DatastoreID).
			AddField("old-relative-URL", oldConfig.RelativeURL).
			AddField("old-format", oldConfig.Format).
			AddField("old-content-sha256", oldConfig.ContentSha256).
			AddField("old-max-download-size-int64", oldConfig.MaxDownloadSize).
			Infof("Content tree config modify")
	}
}

// LogDelete :
func (config ContentTreeConfig) LogDelete() {
	logObject := base.EnsureLogObject(base.ContentTreeConfigLogType, config.DisplayName,
		config.ContentID, config.LogKey())
	logObject.CloneAndAddField("datastore-id", config.DatastoreID).
		AddField("relative-URL", config.RelativeURL).
		AddField("format", config.Format).
		AddField("content-sha256", config.ContentSha256).
		AddField("max-download-size-int64", config.MaxDownloadSize).
		Infof("Content tree config delete")

	base.DeleteLogObject(config.LogKey())
}

// LogKey :
func (config ContentTreeConfig) LogKey() string {
	return string(base.ContentTreeConfigLogType) + "-" + config.Key()
}

// ContentTreeStatus is response from volumemgr about status of content tree
type ContentTreeStatus struct {
	ContentID         uuid.UUID
	DatastoreID       uuid.UUID
	RelativeURL       string
	Format            zconfig.Format
	ContentSha256     string
	MaxDownloadSize   uint64
	GenerationCounter int64
	ImageSignature    []byte   //signature of image
	SignatureKey      string   //certificate containing public key
	CertificateChain  []string //name of intermediate certificates
	DisplayName       string
	HasResolverRef    bool
	HasDownloaderRef  bool
	HasVerifierRef    bool
	WaitingForCerts   bool
	State             SwState
	Progress          uint   // In percent i.e., 0-100
	FileLocation      string // Location of filestystem
	ObjType           string
	NameIsURL         bool

	ErrorAndTimeWithSource
}

// Key is content info UUID which will be unique
func (status ContentTreeStatus) Key() string {
	return status.ContentID.String()
}

// ResolveKey will return the key of resolver config/status
func (status ContentTreeStatus) ResolveKey() string {
	return fmt.Sprintf("%s+%s+%v", status.DatastoreID.String(),
		status.RelativeURL, status.GenerationCounter)
}

// IsContainer will return true if content tree is of container type
func (status ContentTreeStatus) IsContainer() bool {
	if status.Format == zconfig.Format_CONTAINER {
		return true
	}
	return false
}

// LogCreate :
func (status ContentTreeStatus) LogCreate() {
	logObject := base.NewLogObject(base.ContentTreeStatusLogType, status.DisplayName,
		status.ContentID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("content-sha256", status.ContentSha256).
		AddField("max-download-size-int64", status.MaxDownloadSize).
		AddField("state", status.State.String()).
		AddField("progress", status.Progress).
		AddField("filelocation", status.FileLocation).
		Infof("Content tree status create")
}

// LogModify :
func (status ContentTreeStatus) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(base.ContentTreeStatusLogType, status.DisplayName,
		status.ContentID, status.LogKey())

	oldStatus, ok := old.(ContentTreeStatus)
	if !ok {
		log.Errorf("LogModify: Old object interface passed is not of ContentTreeStatus type")
	}
	if oldStatus.ContentSha256 != status.ContentSha256 ||
		oldStatus.MaxDownloadSize != status.MaxDownloadSize ||
		oldStatus.State != status.State ||
		oldStatus.Progress != status.Progress ||
		oldStatus.FileLocation != status.FileLocation {

		logObject.CloneAndAddField("content-sha256", status.ContentSha256).
			AddField("max-download-size-int64", status.MaxDownloadSize).
			AddField("state", status.State.String()).
			AddField("progress", status.Progress).
			AddField("filelocation", status.FileLocation).
			AddField("old-content-sha256", oldStatus.ContentSha256).
			AddField("old-max-download-size-int64", oldStatus.MaxDownloadSize).
			AddField("old-state", oldStatus.State.String()).
			AddField("old-progress", oldStatus.Progress).
			AddField("old-filelocation", oldStatus.FileLocation).
			Infof("Content tree status modify")
	}
}

// LogDelete :
func (status ContentTreeStatus) LogDelete() {
	logObject := base.EnsureLogObject(base.ContentTreeStatusLogType, status.DisplayName,
		status.ContentID, status.LogKey())
	logObject.CloneAndAddField("content-sha256", status.ContentSha256).
		AddField("max-download-size-int64", status.MaxDownloadSize).
		AddField("state", status.State.String()).
		AddField("progress", status.Progress).
		AddField("filelocation", status.FileLocation).
		Infof("Content tree status delete")

	base.DeleteLogObject(status.LogKey())
}

// LogKey :
func (status ContentTreeStatus) LogKey() string {
	return string(base.ContentTreeStatusLogType) + "-" + status.Key()
}

// IsCertsAvailable checks certificate requirement/availability for a content tree object
func (status ContentTreeStatus) IsCertsAvailable(displaystr string) (bool, error) {
	if !status.needsCerts() {
		log.Debugf("%s, Certs are not required\n", displaystr)
		return false, nil
	}
	cidx, err := status.getCertCount(displaystr)
	return cidx != 0, err
}

// needsCerts whether certificates are required for the content tree object
func (status ContentTreeStatus) needsCerts() bool {
	if len(status.ImageSignature) == 0 {
		return false
	}
	return true
}

// getCertCount returns the number of certificates for the content tree Object
// called with valid ImageSignature only
func (status ContentTreeStatus) getCertCount(displaystr string) (int, error) {
	cidx := 0
	if status.SignatureKey == "" {
		errStr := fmt.Sprintf("%s, Invalid Root CertURL\n", displaystr)
		log.Errorf(errStr)
		return cidx, errors.New(errStr)
	}
	cidx++
	if len(status.CertificateChain) != 0 {
		for _, certURL := range status.CertificateChain {
			if certURL == "" {
				errStr := fmt.Sprintf("%s, Invalid Intermediate CertURL\n", displaystr)
				log.Errorf(errStr)
				return 0, errors.New(errStr)
			}
			cidx++
		}
	}
	return cidx, nil
}

// HandleCertStatus gets the CertObject Status for the content tree object
// True, when there is no Certs or, the certificates are ready
// False, Certificates are not ready or, there are some errors
func (status ContentTreeStatus) HandleCertStatus(displaystr string,
	certObjStatus CertObjStatus) (bool, ErrorAndTime) {
	if ret, errInfo := status.checkCertsStatusForObject(certObjStatus); !ret {
		log.Infof("%s, Certs are still not ready\n", displaystr)
		return ret, errInfo
	}
	if ret := status.checkCertsForObject(); !ret {
		log.Infof("%s, Certs are still not installed\n", displaystr)
		return ret, ErrorAndTime{}
	}
	return true, ErrorAndTime{}
}

// checkCertsStatusForObject checks certificates for installation status
func (status ContentTreeStatus) checkCertsStatusForObject(certObjStatus CertObjStatus) (bool, ErrorAndTime) {

	if status.SignatureKey != "" {
		found, installed, errInfo := certObjStatus.getCertStatus(status.SignatureKey)
		if !found || !installed {
			return false, errInfo
		}
	}

	for _, certURL := range status.CertificateChain {
		found, installed, errorAndTime := certObjStatus.getCertStatus(certURL)
		if !found || !installed {
			return false, errorAndTime
		}
	}
	return true, ErrorAndTime{}
}

// checkCertsForObject checks availability of Certs in Disk
func (status ContentTreeStatus) checkCertsForObject() bool {

	if status.SignatureKey != "" {
		safename := UrlToSafename(status.SignatureKey, "")
		filename := CertificateDirname + "/" + SafenameToFilename(safename)
		// XXX result is just the sha? Or "serverCert.<sha>?
		if _, err := os.Stat(filename); err != nil {
			log.Errorf("checkCertsForObject() for %s, %v\n", filename, err)
			return false
		}
		// XXX check for valid or non-zero length?
	}

	for _, certURL := range status.CertificateChain {
		safename := UrlToSafename(certURL, "")
		filename := CertificateDirname + "/" + SafenameToFilename(safename)
		// XXX result is just the sha? Or "serverCert.<sha>?
		if _, err := os.Stat(filename); err != nil {
			log.Errorf("checkCertsForObject() for %s, %v\n", filename, err)
			return false
		}
		// XXX check for valid or non-zero length?
	}

	for _, certURL := range status.CertificateChain {
		safename := UrlToSafename(certURL, "")
		filename := CertificateDirname + "/" + SafenameToFilename(safename)
		// XXX result is just the sha? Or "serverCert.<sha>?
		if _, err := os.Stat(filename); err != nil {
			log.Errorf("checkCertsForObject() for %s, %v\n", filename, err)
			return false
		}
		// XXX check for valid or non-zero length?
	}
	return true
}
