// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
//
//go:build k

package hypervisor

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "kubevirt.io/api/core/v1"
)

func TestSetTerminationGracePeriod(t *testing.T) {
	spec := &v1.VirtualMachineInstanceSpec{}
	setTerminationGracePeriod(spec)

	if assert.NotNil(t, spec.TerminationGracePeriodSeconds,
		"an unset field leaves KubeVirt applying its own 30s default") {
		assert.Equal(t, int64(GracefulShutdownWait/time.Second),
			*spec.TerminationGracePeriodSeconds)
	}
}
