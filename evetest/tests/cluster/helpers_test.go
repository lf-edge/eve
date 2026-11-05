// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cluster_test

import (
	"fmt"
	"strings"
	"time"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
)

// k3sTokenFile is where k3s records the token its datastore is encrypted
// with, rewritten by k3s on every rotation. A k3s path rather than an EVE
// internal, read because the EVE API does not show which token a running
// cluster uses.
const k3sTokenFile = "/var/lib/rancher/k3s/server/token"

// clusterReports is the latest cluster info of each device that has one.
type clusterReports []*eveinfo.ZInfoKubeCluster

func (r clusterReports) String() string {
	parts := make([]string, len(r))
	for i, info := range r {
		parts[i] = info.String()
	}
	return "[" + strings.Join(parts, "; ") + "]"
}

// latestClusterReports returns the latest cluster info of each of devNames.
// Only the stats leader publishes cluster info, and only when it changes, so
// asserting on the current state means reading the latest report of every
// candidate rather than waiting for a new one that may never be sent.
func latestClusterReports(devNames []string) clusterReports {
	var reports clusterReports
	for _, name := range devNames {
		if info, _ := evetest.GetEdgeDevice(name).GetClusterInfo(); info != nil {
			reports = append(reports, info)
		}
	}
	return reports
}

// anyReport lifts pred to clusterReports: true if any report satisfies it.
func anyReport(pred func(*eveinfo.ZInfoKubeCluster) bool) func(clusterReports) bool {
	return func(reports clusterReports) bool {
		for _, info := range reports {
			if pred(info) {
				return true
			}
		}
		return false
	}
}

// k3sRunsToken reports whether the token k3s recorded on dev, which k3s
// rewrites on a rotation, carries the secret token.
func k3sRunsToken(dev *evetest.EdgeDevice, token string) (bool, error) {
	out, _, err := dev.RunShellScript("eve exec kube cat "+k3sTokenFile, time.Minute, 0)
	if err != nil {
		return false, err
	}
	return strings.HasSuffix(strings.TrimSpace(out), "::server:"+token), nil
}

// k3sNodeReady asks the apiserver on dev itself whether nodeName is Ready, so
// a true answer also proves k3s on dev is up.
func k3sNodeReady(dev *evetest.EdgeDevice, nodeName string) (bool, error) {
	out, err := dev.RunKubectl(fmt.Sprintf(
		`get node %s -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}'`,
		nodeName), time.Minute)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == "True", nil
}
