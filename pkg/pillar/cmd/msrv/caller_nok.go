// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !k

package msrv

import (
	"context"
	"errors"
)

func (msrv *Msrv) addKubePodIdentity(context.Context, *CallerIdentity, string) error {
	return errors.New("Kubernetes workloads exist only on EVE-k")
}
