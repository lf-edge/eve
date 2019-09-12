// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

const (
	appImgObj = "appImg.obj"

	// TmpDirname - Temporary dir for zededa components
	TmpDirname = "/var/tmp/zededa"
	// PersistDir - Persist Directory
	PersistDir = "/persist"
	// PersistRktDataDir - persist rkt dir used by rkt
	PersistRktDataDir = PersistDir + "/rkt"
	// RwImgDirname - location for images
	RwImgDirname = PersistDir + "/img" // We store images here
	// DownloadDirname - Location for downloader to download images
	DownloadDirname = PersistDir + "/downloads"
	// ImgCatalogDirname - Location for App Images
	ImgCatalogDirname = DownloadDirname + "/" + appImgObj
	// VerifiedDirname - Read-only images named based on sha256 hash each
	// in its own directory
	VerifiedDirname = ImgCatalogDirname + "/verified"
)
