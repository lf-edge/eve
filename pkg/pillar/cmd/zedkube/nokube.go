// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !kubevirt

package zedkube

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/sirupsen/logrus"
)

// Run in this file is just stub for non-kubevirt hypervisors.
func Run(*pubsub.PubSub, *logrus.Logger, *base.LogObject, []string) int {
	panic("zedkube microservice is not built")
}
