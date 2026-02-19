// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kubeapi

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

func ensureKubeRuntime(op string) error {
	if base.IsHVTypeKube() {
		return nil
	}
	return fmt.Errorf("%s: kube runtime is not enabled", op)
}
