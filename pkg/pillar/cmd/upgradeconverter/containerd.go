// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	utils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

func moveToUserContainerd(ctxPtr *ucContext) error {
	log.Functionf("moveToUserContainerd()")
	return utils.MoveDir(ctxPtr.persistDir+"/containerd", ctxPtr.persistDir+"/vault/containerd")
}
