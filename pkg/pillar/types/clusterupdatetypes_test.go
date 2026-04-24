// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/stretchr/testify/assert"
)

// KubeCompUpdateStatusFromStr

func TestKubeCompUpdateStatusFromStr(t *testing.T) {
	cases := []struct {
		input string
		want  KubeCompUpdateStatus
	}{
		{"download", CompStatusDownload},
		{"download_failed", CompStatusDownloadFailed},
		{"in_progress", CompStatusInProgress},
		{"failed", CompStatusFailed},
		{"completed", CompStatusCompleted},
		{"unknown", CompStatusUnknown},
		{"", CompStatusUnknown},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, KubeCompUpdateStatusFromStr(tc.input), "input=%q", tc.input)
	}
}

// KubeCompUpdateStatus.KubeCompUpdateStatus (to proto)

func TestKubeCompUpdateStatusToProto(t *testing.T) {
	cases := []struct {
		state KubeCompUpdateStatus
		want  info.KubeCompUpdateStatus
	}{
		{CompStatusDownload, info.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_DOWNLOAD},
		{CompStatusDownloadFailed, info.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_DOWNLOAD_FAILED},
		{CompStatusInProgress, info.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_IN_PROGRESS},
		{CompStatusFailed, info.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_FAILED},
		{CompStatusCompleted, info.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_COMPLETED},
		{CompStatusUnknown, info.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_UNSPECIFIED},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.state.KubeCompUpdateStatus())
	}
}

// KubeCompFromStr

func TestKubeCompFromStr(t *testing.T) {
	cases := []struct {
		input string
		want  KubeComp
	}{
		{"containerd", CompContainerd},
		{"k3s", CompK3s},
		{"multus", CompMultus},
		{"kubevirt", CompKubevirt},
		{"cdi", CompCdi},
		{"longhorn", CompLonghorn},
		{"", CompUnknown},
		{"bad", CompUnknown},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, KubeCompFromStr(tc.input), "input=%q", tc.input)
	}
}

// KubeComp.KubeComp (to proto)

func TestKubeCompToProto(t *testing.T) {
	cases := []struct {
		comp KubeComp
		want info.KubeComp
	}{
		{CompContainerd, info.KubeComp_KUBE_COMP_CONTAINERD},
		{CompK3s, info.KubeComp_KUBE_COMP_K3S},
		{CompMultus, info.KubeComp_KUBE_COMP_MULTUS},
		{CompKubevirt, info.KubeComp_KUBE_COMP_KUBEVIRT},
		{CompCdi, info.KubeComp_KUBE_COMP_CDI},
		{CompLonghorn, info.KubeComp_KUBE_COMP_LONGHORN},
		{CompUnknown, info.KubeComp_KUBE_COMP_UNSPECIFIED},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.comp.KubeComp())
	}
}
