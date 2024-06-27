// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"path/filepath"

	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

const (
	srcDir  = "/zedrouter/AppInstMetaData"
	destDir = "/msrv/AppInstMetaData"
)

func movePersistPubsub(ctxPtr *ucContext) error {
	src := filepath.Join(ctxPtr.persistStatusDir, srcDir)
	dst := filepath.Join(ctxPtr.persistStatusDir, destDir)

	srcExists := fileutils.DirExists(log, src)
	dstExists := fileutils.DirExists(log, dst)

	if srcExists && !dstExists {
		return fileutils.CopyDir(src, dst)
	}

	return nil
}
