// Copyright (c) 2024-2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
//
//go:build kubevirt

package hypervisor

import (
	"net"
	"os"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// k3sPem is used for a mock k3s.yaml file
const k3sPem = `apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJlRENDQVIyZ0F3SUJBZ0lCQURBS0JnZ3Foa2pPUFFRREFqQWpNU0V3SHdZRFZRUUREQmhyTTNNdGMyVnkKZG1WeUxXTmhRREUzTWpnME1UTXpOelV3SGhjTk1qUXhNREE0TVRnME9UTTFXaGNOTXpReE1EQTJNVGcwT1RNMQpXakFqTVNFd0h3WURWUVFEREJock0zTXRjMlZ5ZG1WeUxXTmhRREUzTWpnME1UTXpOelV3V1RBVEJnY3Foa2pPClBRSUJCZ2dxaGtqT1BRTUJCd05DQUFRMWVZSEVBL2JZTUdyQ3oxV2ZlaUdmR1BuVE5TNkd3SjA0enRFVzNydjYKeWd3cElvYnhTR25GRXpTYTFSbDZpT0J5SE15MkdmdWdTMGkvQzVnSzJhaStvMEl3UURBT0JnTlZIUThCQWY4RQpCQU1DQXFRd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBZEJnTlZIUTRFRmdRVXQ1MThHdnNwZjJYOEwzTUxZREx2CllKUk9mNE13Q2dZSUtvWkl6ajBFQXdJRFNRQXdSZ0loQUpxdFFob3FaV2lLUWVwYnphTTFQcmtNWVk2KzFEekkKUllIdHF4cjhPQnAzQWlFQTlrNnNOcEhOemxXRW9XMHFkbmI2Q0pnWVBXenJsdW5YcjRrUmNKWUtpRzA9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K
    server: https://127.0.0.1:6443
  name: default
contexts:
- context:
    cluster: default
    user: default
  name: default
current-context: default
kind: Config
preferences: {}
users:
- name: default
  user:
    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJrVENDQVRlZ0F3SUJBZ0lJRG1FcTFOaTZGdDR3Q2dZSUtvWkl6ajBFQXdJd0l6RWhNQjhHQTFVRUF3d1kKYXpOekxXTnNhV1Z1ZEMxallVQXhOekk0TkRFek16YzFNQjRYRFRJME1UQXdPREU0TkRrek5Wb1hEVEkxTVRBdwpPREU0TkRrek5Wb3dNREVYTUJVR0ExVUVDaE1PYzNsemRHVnRPbTFoYzNSbGNuTXhGVEFUQmdOVkJBTVRESE41CmMzUmxiVHBoWkcxcGJqQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJGR01VS2R4VFJobVR2MlcKNm50Z2UyVm9VUXRuWFRpeWpBTUptL01STTdkbnRTa3g5OXRGWGJUNUMxSUhkQmVLMXFSZ3RXclpjMmlZcWNMYQpzTTVVTlg2alNEQkdNQTRHQTFVZER3RUIvd1FFQXdJRm9EQVRCZ05WSFNVRUREQUtCZ2dyQmdFRkJRY0RBakFmCkJnTlZIU01FR0RBV2dCUzRIZjU3TjU1Nzl6ajRyTVdqK0hvSWp0MWcyakFLQmdncWhrak9QUVFEQWdOSUFEQkYKQWlCK0d2cDMwQnJJazk4UzZUeVdXbzI0VmRNZU1JZkdheW90REhhb0NsTnFrQUloQUxZTnZQK3dwTVFFV2pHRApkMDRvTWh0ckN3akNUblZFT3pvMXRtV3lQK0ZOCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJkakNDQVIyZ0F3SUJBZ0lCQURBS0JnZ3Foa2pPUFFRREFqQWpNU0V3SHdZRFZRUUREQmhyTTNNdFkyeHAKWlc1MExXTmhRREUzTWpnME1UTXpOelV3SGhjTk1qUXhNREE0TVRnME9UTTFXaGNOTXpReE1EQTJNVGcwT1RNMQpXakFqTVNFd0h3WURWUVFEREJock0zTXRZMnhwWlc1MExXTmhRREUzTWpnME1UTXpOelV3V1RBVEJnY3Foa2pPClBRSUJCZ2dxaGtqT1BRTUJCd05DQUFRaXBVL3BoeWtINHFBYThsK3VwZmhtUk43M2tsbFI3VnhiZ1FGMU5GemcKTVRvUk5zSkxaYnFIY1NpMkk4RnMvNnBPZ1g4TlBlUHVOb01YYlFqaGJJTW9vMEl3UURBT0JnTlZIUThCQWY4RQpCQU1DQXFRd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBZEJnTlZIUTRFRmdRVXVCMytlemVlZS9jNCtLekZvL2g2CkNJN2RZTm93Q2dZSUtvWkl6ajBFQXdJRFJ3QXdSQUlnZklMeDNVUTlwZ2Z3VmZCRmh5aEo2YUhMeGkyQk03aGQKZ0YwalNhc1U1UndDSUE0OFN6NXpkaVhoNFJpdTVlZ2NtRnBXdkpyMXRKc1dCS25PQWt3clExdFgKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
    client-key-data: LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUNRK1NkV2QrdkwwaE5DOU4yeTVFMUxmMzF6a0I2SHdvTUw3UlVFTkZVTWpvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFVVl4UXAzRk5HR1pPL1picWUyQjdaV2hSQzJkZE9MS01Bd21iOHhFenQyZTFLVEgzMjBWZAp0UGtMVWdkMEY0cldwR0MxYXRsemFKaXB3dHF3emxRMWZnPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo=`

// TestCreateReplicaPodConfig tests the CreateReplicaPodConfig function
func TestCreateReplicaPodConfig(t *testing.T) {
	// Set up sample inputs
	domainName := "test-domain"
	uuidValue, err := uuid.NewV4()
	assert.NoError(t, err)

	config := types.DomainConfig{
		DisplayName:    "test-app",
		UUIDandVersion: types.UUIDandVersion{UUID: uuidValue},
		KubeImageName:  "test-image",
		VifList: []types.VifConfig{
			{Vif: "vif0", Bridge: "br0", Mac: net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}},
			{Vif: "vif1", Bridge: "br0", Mac: net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x57}},
		},
	}
	status := types.DomainStatus{}

	diskStatusList := []types.DiskStatus{
		{
			VolumeKey:    "3b2337e6-2488-4ff6-87c6-b3a6d918b325#0",
			FileLocation: "3b2337e6-2488-4ff6-87c6-b3a6d918b325-pvc-0",
			ReadOnly:     false,
			Format:       8, // container type
			MountDir:     "/",
			DisplayName:  "my-app_0_m_0",
			WWN:          "",
			CustomMeta:   "",
		},
		{
			VolumeKey:    "f6e9139f-eba3-4480-821a-d1af8ca5dd07#0",
			ReadOnly:     false,
			FileLocation: "f6e9139f-eba3-4480-821a-d1af8ca5dd07-pvc-0",
			Format:       10, // pvc type (block device)
			MountDir:     "",
			DisplayName:  "example-longer-eve-node-name1-app-name-1-ef059340-5838-4639-b115-fa3790c6734d",
			Devtype:      "hdd",
			Vdev:         "xvdb",
			WWN:          "",
			CustomMeta:   "",
		},
		{
			VolumeKey:    "",
			ReadOnly:     false,
			FileLocation: "/mnt",
			Format:       0, // pvc type (block device)
			MountDir:     "",
			DisplayName:  "",
			Devtype:      "9P",
			Vdev:         "",
			WWN:          "",
			CustomMeta:   "",
		},
	}

	aa := &types.AssignableAdapters{}
	file, err := os.CreateTemp("", "testfile")
	assert.NoError(t, err)
	defer os.Remove(file.Name())

	// Set up kubevirtContext
	ctx := kubevirtContext{
		devicemodel:      "virt",
		vmiList:          make(map[string]*vmiMetaData),
		prevDomainMetric: make(map[string]types.DomainMetric),
		nodeNameMap:      map[string]string{"nodename": "test-node"},
	}

	// Mock the /run/.kube/k3s/k3s.yaml file
	kubeConfigPath := "/run/.kube/k3s/k3s.yaml"
	err = os.MkdirAll("/run/.kube/k3s", 0755)
	assert.NoError(t, err)
	mockFile, err := os.Create(kubeConfigPath)
	assert.NoError(t, err)
	defer os.Remove(kubeConfigPath)
	defer mockFile.Close()

	_, err = mockFile.WriteString(k3sPem)
	assert.NoError(t, err)

	// Call the function to create the replicaSet of pod configure
	err = ctx.CreateReplicaPodConfig(domainName, config, status, diskStatusList, aa, file)
	assert.NoError(t, err)

	// Additional checks and assertions similar to the Start function
	nodeName, ok := ctx.nodeNameMap["nodename"]
	assert.True(t, ok, "Failed to get nodeName from map")

	err = getConfig(&ctx)
	assert.NoError(t, err)
	kubeconfig := ctx.kubeConfig
	assert.NotNil(t, kubeconfig, "kubeConfig should not be nil")

	// Check the Pod ReplicaSet
	logrus.Infof("Checking Kubevirt domain %s, nodename %s", domainName, nodeName)
	vmis, ok := ctx.vmiList[domainName]
	assert.True(t, ok, "check domain %s failed to get vmlist", domainName)

	assert.True(t, vmis.mtype == IsMetaReplicaPod, "check domain %s failed to get type", domainName)

	replicaPod := vmis.repPod
	assert.NotNil(t, replicaPod, "replicaPod should not be nil")

	assert.Equal(t, replicaPod.ObjectMeta.Name, vmis.name, "replicaPod name %s is different from name %s",
		replicaPod.ObjectMeta.Name, vmis.name)

	assert.True(t, len(replicaPod.Spec.Template.Spec.Volumes) > 0, "ReplicaSet volumes missing")
	mountLen := len(replicaPod.Spec.Template.Spec.Containers[0].VolumeMounts)
	assert.True(t, mountLen == 0, "ReplicaSet incorrect volume mount len %d", mountLen)
	devLen := len(replicaPod.Spec.Template.Spec.Containers[0].VolumeDevices)
	assert.True(t, devLen == 1, "ReplicaSet incorrect volumedevice len %d", devLen)
}
