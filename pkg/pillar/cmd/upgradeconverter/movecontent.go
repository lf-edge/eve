// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	utils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

//convertContainerdContentAndMount move content of containerd's content plugin to encrypted directory and mount it
func convertContainerdContentAndMount(ctxPtr *ucContext) error {
	log.Functionf("convertContainerdContentAndMount()")
	contentDirContainerd := filepath.Join(ctxPtr.persistDir, "containerd", "io.containerd.content.v1.content")
	contentDirEVE := filepath.Join(ctxPtr.persistDir, "vault", "eve.content")
	err := utils.MoveDir(contentDirContainerd, contentDirEVE)
	if err != nil {
		return fmt.Errorf("convertContainerdContentAndMount MoveDir failed: %v", err)
	}
	err = os.RemoveAll(contentDirContainerd)
	if err != nil {
		return fmt.Errorf("convertContainerdContentAndMount remove all failed: %v", err)
	}
	err = os.Mkdir(contentDirContainerd, os.ModeDir)
	if err != nil {
		return fmt.Errorf("convertContainerdContentAndMount mkdir failed: %v", err)
	}
	err = syscall.Mount(contentDirEVE, contentDirContainerd, "", syscall.MS_BIND, "")
	if err != nil {
		return fmt.Errorf("convertContainerdContentAndMount bind mount failed: %v", err)
	}
	return nil
}
