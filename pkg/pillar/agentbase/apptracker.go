// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package agentbase

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// LocalTriState wraps the types.TriState type
// for JSON marshaling purposes
type LocalTriState types.TriState

// AppVolume - the struct for the Volume ID and Content ID
type AppVolume struct {
	VolumeID  string
	ContentID string
}

// AppInternalCfg - the struct for the internal App configuration
type AppInternalCfg struct {
	AppUUID     string
	DisplayName string
	AppNumber   int

	AppVolumes []AppVolume
	NetworkID  []string
}

// AppInfoItems - the generic struct for the App and cluster info
type AppInfoItems struct {
	UUID      string
	Name      string
	Exist     bool
	Activated LocalTriState
	State     string
	Content   string
	DNidNode  LocalTriState
	Errors    string
}

// OrderedAppInfoItem - the struct for key/value
type OrderedAppInfoItem struct {
	Key   string       `json:"key"`
	Value AppInfoItems `json:"value"`
}

// AppTrackerInfo - the struct for the App and cluster info per node
type AppTrackerInfo struct {
	Hostname    string               `json:"hostname"`
	CollectTime string               `json:"collectTime"`
	AppInfo     []OrderedAppInfoItem `json:"appInfo"`
}

// GetApplicationInfo - get Cluster and App related microservices key info from their publications.
// this library function by given the App-UUID, it can be empty, and returns the node hostname
// and an array of each of the publication items for debugging purpose.
// This function can be called from 'zedkube' HTTP handler function on the live node, or
// it can be called from offline for processing the same microservice publications in eve-info data
// of the 'collect-info'. The publication directory locations are passed in to handle the various usages.
func GetApplicationInfo(rootRun, persistStatus, persistKubelog, AppUUID string) AppTrackerInfo {
	var appInfo []OrderedAppInfoItem
	var err error

	// 1) Get the Node Info
	structName := "zedagent-EdgeNodeInfo"
	nodeInfo := &types.EdgeNodeInfo{}
	if structName, err = readJSONFile(persistStatus, structName, "global", nodeInfo); err != nil {
		return addHostnameAppInfo("unknown", appendFailedItem(appInfo, structName, "global", err))
	}
	ai := AppInfoItems{ // EdgeNodeInfo
		UUID:    nodeInfo.DeviceID.String(),
		Name:    nodeInfo.DeviceName,
		Exist:   true,
		Content: fmt.Sprintf("Enterprise: %s, Project: %s", nodeInfo.EnterpriseName, nodeInfo.ProjectName),
	}
	appInfo = append(appInfo, OrderedAppInfoItem{Key: structName, Value: ai})

	hostname := nodeInfo.DeviceName

	// 2) Get the EdgeNodeClusterStatus, may not exist
	structName = "zedkube-EdgeNodeClusterStatus"
	clusterStatus := &types.EdgeNodeClusterStatus{}
	if structName, err = readJSONFile(rootRun, structName, "global", clusterStatus); err != nil {
		appInfo = appendFailedItem(appInfo, structName, "global", err)
	} else {
		ClusterIPReady := "Cluster IP Not Ready"
		if clusterStatus.ClusterIPIsReady {
			ClusterIPReady = "Cluster IP Ready"
		}
		ai := AppInfoItems{ // EdgeNodeClusterStatus
			UUID:    "global",
			Name:    clusterStatus.ClusterInterface,
			Exist:   true,
			State:   ClusterIPReady,
			Content: fmt.Sprintf("ClusterIP %v, JoinIP %v, Bootstrap %v", clusterStatus.ClusterIPPrefix, clusterStatus.JoinServerIP, clusterStatus.BootstrapNode),
		}
		appInfo = append(appInfo, OrderedAppInfoItem{Key: structName, Value: ai})
	}

	// 3) Get the KubeLeaseInfo from zedkuube, it may not exist
	var structName2 string
	structName = "zedkube-KubeLeaseInfo"
	leaseInfo := &types.KubeLeaseInfo{}
	if structName2, err = readJSONFile(rootRun, structName, "global", leaseInfo); err != nil {
		appInfo = appendFailedItem(appInfo, structName, "global", err)
	} else {
		ai = AppInfoItems{ // ENClusterAppStatus
			UUID:      "global",
			Name:      leaseInfo.LeaderIdentity,
			Exist:     true,
			State:     fmt.Sprintf("Is Stats Leader %v", leaseInfo.IsStatsLeader),
			Activated: boolToTriState(leaseInfo.InLeaseElection),
			Content:   fmt.Sprintf("Last time updated at %v", leaseInfo.LatestChange.UTC().Format(time.RFC3339)),
		}
		appInfo = append(appInfo, OrderedAppInfoItem{Key: structName2, Value: ai})
	}

	// 4) tail the last 10 lines of k3s-install.log
	structName = "k3s-install.log"
	readStrings, err := getTailOfK3sInstallLog(persistKubelog)
	if err == nil {
		ai = AppInfoItems{ // AppInstanceConfig
			Name:    "k3s-install.log",
			Exist:   true,
			Content: readStrings,
		}
		appInfo = append(appInfo, OrderedAppInfoItem{Key: structName, Value: ai})
	}

	// if not for a specific AppUUID, return here
	if AppUUID == "" {
		return addHostnameAppInfo(hostname, appInfo)
	}

	// 5) Get the AppInstacneConfig
	structName = "zedagent-AppInstanceConfig"
	appInstanceConfig := &types.AppInstanceConfig{}
	if structName, err = readJSONFile(rootRun, structName, AppUUID, appInstanceConfig); err != nil {
		return addHostnameAppInfo(hostname, appendFailedItem(appInfo, structName, AppUUID, err))
	}
	ai = AppInfoItems{ // AppInstanceConfig
		UUID:      AppUUID,
		Name:      appInstanceConfig.DisplayName,
		Exist:     true,
		Activated: boolToTriState(appInstanceConfig.Activate),
		DNidNode:  boolToTriState(appInstanceConfig.IsDesignatedNodeID),
	}
	appInfo = append(appInfo, OrderedAppInfoItem{Key: structName, Value: ai})

	appInternal := &AppInternalCfg{
		AppUUID:     AppUUID,
		DisplayName: appInstanceConfig.DisplayName,
	}

	// 6) Get the VolumeConfig in the App
	for _, appVolume := range appInstanceConfig.VolumeRefConfigList {
		structName2 := "zedagent-VolumeConfig"
		volumeConfig := &types.VolumeConfig{}
		if structName2, err = readJSONFile(rootRun, structName2, appVolume.VolumeID.String(), volumeConfig); err != nil {
			return addHostnameAppInfo(hostname, appendFailedItem(appInfo, structName2, appVolume.VolumeID.String(), err))
		}
		vol := AppVolume{
			VolumeID:  volumeConfig.VolumeID.String(),
			ContentID: volumeConfig.ContentID.String(),
		}
		appInternal.AppVolumes = append(appInternal.AppVolumes, vol)
		ai = AppInfoItems{ // VolumeConfig
			UUID:    appVolume.VolumeID.String(),
			Name:    volumeConfig.DisplayName,
			Exist:   true,
			Content: fmt.Sprintf("ContentID: %s, replicated %v", volumeConfig.ContentID.String(), volumeConfig.IsReplicated),
		}
		appInfo = append(appInfo, OrderedAppInfoItem{Key: structName2, Value: ai})
	}

	// Get the Network Instance IDs in the App
	for _, network := range appInstanceConfig.AppNetAdapterList {
		appInternal.NetworkID = append(appInternal.NetworkID, network.Network.String())
	}

	for i, item := range appInfo {
		if item.Key == structName {
			item.Value.Content = fmt.Sprintf("Volume Counts %d, Network Counts %d", len(appInternal.AppVolumes), len(appInternal.NetworkID))
			appInfo[i] = item
		}
	}

	// 7) Get all the Network Instance Status, they have to exist, otherwise return here
	for _, netID := range appInternal.NetworkID {
		var structName2 string
		structName = "zedrouter-NetworkInstanceStatus"
		niStatus := &types.NetworkInstanceStatus{}
		if structName2, err = readJSONFile(rootRun, structName, netID, niStatus); err != nil {
			return addHostnameAppInfo(hostname, appendFailedItem(appInfo, structName, netID, err))
		}
		ai = AppInfoItems{ // NetworkInstanceStatus
			UUID:      netID,
			Name:      niStatus.DisplayName,
			Exist:     true,
			Activated: boolToTriState(niStatus.Activated),
			Content:   fmt.Sprintf("ip assignments %v", niStatus.IPAssignments),
		}
		appInfo = append(appInfo, OrderedAppInfoItem{Key: structName2, Value: ai})
	}

	// 8) Get the ENClusterAppStatus from zedkuube, it may not exist
	structName = "zedkube-ENClusterAppStatus"
	enClusterAppStatus := &types.ENClusterAppStatus{}
	if structName2, err = readJSONFile(rootRun, structName, AppUUID, enClusterAppStatus); err != nil {
		appInfo = appendFailedItem(appInfo, structName, AppUUID, err)
	} else {
		ai = AppInfoItems{ // ENClusterAppStatus
			UUID:     AppUUID,
			Exist:    true,
			DNidNode: boolToTriState(enClusterAppStatus.IsDNidNode),
			Content:  fmt.Sprintf("Scheduled on this node %v, StatusRunning %v", enClusterAppStatus.ScheduledOnThisNode, enClusterAppStatus.StatusRunning),
		}
		appInfo = append(appInfo, OrderedAppInfoItem{Key: structName2, Value: ai})
	}

	// 9) Get the AppNetworkConfig for the App from zedmanager, it may not exist
	structName = "zedmanager-AppNetworkConfig"
	appNetCfg := &types.AppNetworkConfig{}
	if structName2, err = readJSONFile(rootRun, structName, AppUUID, appNetCfg); err != nil {
		appInfo = appendFailedItem(appInfo, structName, AppUUID, err)
	} else {
		var assignedIPs []string
		var appMacs []string
		var intfName []string
		for _, appnetst := range appNetCfg.AppNetAdapterList {
			intfName = append(intfName, appnetst.Name)
			appMacs = append(appMacs, appnetst.AppMacAddr.String())
			assignedIPs = append(assignedIPs, appnetst.AppIPAddr.String())
		}
		ai = AppInfoItems{ // AppNetworkStatus
			UUID:      AppUUID,
			Name:      appNetCfg.DisplayName,
			Exist:     true,
			Activated: boolToTriState(appNetCfg.Activate),
			Content:   fmt.Sprintf("App-Intf %v, App-Mac %v, App-IPs %v", intfName, appMacs, assignedIPs),
		}
		appInfo = append(appInfo, OrderedAppInfoItem{Key: structName2, Value: ai})
	}

	// 10) Get the AppNetworkStatus for the App, it may not exist
	structName = "zedrouter-AppNetworkStatus"
	appNetStatus := &types.AppNetworkStatus{}
	if structName2, err = readJSONFile(rootRun, structName, AppUUID, appNetStatus); err != nil {
		appInfo = appendFailedItem(appInfo, structName, AppUUID, err)
	} else {
		var assignedIPs []string
		for _, appnetst := range appNetStatus.AppNetAdapterList {
			aIP := fmt.Sprintf("%v", appnetst.AssignedAddresses.IPv4Addrs)
			assignedIPs = append(assignedIPs, aIP)
		}
		ai = AppInfoItems{ // AppNetworkStatus
			UUID:      AppUUID,
			Name:      appNetStatus.DisplayName,
			Exist:     true,
			Activated: boolToTriState(appNetStatus.Activated),
			Content:   fmt.Sprintf("App-Num %d, assigned IPs %v", appNetStatus.AppNum, assignedIPs),
		}
		appInfo = append(appInfo, OrderedAppInfoItem{Key: structName2, Value: ai})
	}

	// 11) Get all the VolumeStatus from volumemgr, it may not exist
	structName = "volumemgr-VolumeStatus"
	for _, volumeID := range appInternal.AppVolumes {
		volStatus := &types.VolumeStatus{}
		if structName2, err = readJSONFile(rootRun, structName, volumeID.VolumeID, volStatus); err != nil {
			appInfo = appendFailedItem(appInfo, structName, volumeID.VolumeID, err)
			continue
		}
		ai = AppInfoItems{ // VolumeStatus
			UUID:    volumeID.VolumeID,
			Name:    "ReferenceName: " + volStatus.ReferenceName,
			Exist:   true,
			State:   volStatus.State.String(),
			Content: fmt.Sprintf("Replicated %v, total %v, current %v", volStatus.IsReplicated, volStatus.TotalSize, volStatus.CurrentSize),
		}
		appInfo = append(appInfo, OrderedAppInfoItem{Key: structName2, Value: ai})
	}

	// 12) Get all the ContentTreeStatus from volumemgr, it may not exist
	structName = "volumemgr-ContentTreeStatus"
	for _, volumeID := range appInternal.AppVolumes {
		contentTreeStatus := &types.ContentTreeStatus{}
		if structName2, err = readJSONFile(rootRun, structName, volumeID.ContentID, contentTreeStatus); err != nil {
			ai = AppInfoItems{
				UUID:   volumeID.ContentID,
				Exist:  false,
				Errors: fmt.Sprintf("ContentTreeStatus not found for ContentID: %s, %v", volumeID.ContentID, err),
			}
			appInfo = appendFailedItem(appInfo, structName, volumeID.ContentID, err)
			continue
		}
		ai = AppInfoItems{ // ContentTreeStatus
			UUID:    volumeID.ContentID,
			Name:    contentTreeStatus.DisplayName,
			Exist:   true,
			State:   contentTreeStatus.State.String(),
			Content: fmt.Sprintf("RelativeURL %s, total %d, current %d", contentTreeStatus.RelativeURL, contentTreeStatus.TotalSize, contentTreeStatus.CurrentSize),
		}
		appInfo = append(appInfo, OrderedAppInfoItem{Key: structName2, Value: ai})
	}

	// 13) Get the AppNetworkConfig from zedmanager, it may not exist
	structName = "zedmanager-AppNetworkConfig"
	appNetConfig := &types.AppNetworkConfig{}
	if structName2, err = readJSONFile(rootRun, structName, AppUUID, appNetConfig); err != nil {
		appInfo = appendFailedItem(appInfo, structName, AppUUID, err)
	} else {
		ai = AppInfoItems{ // AppNetworkConfig
			UUID:      AppUUID,
			Name:      appNetConfig.DisplayName,
			Exist:     true,
			Activated: boolToTriState(appNetConfig.Activate),
		}
		appInfo = append(appInfo, OrderedAppInfoItem{Key: structName2, Value: ai})
	}

	// 14) Get the AppInstanceStatus from zedmanager, it may not exist
	structName = "zedmanager-AppInstanceStatus"
	appInstanceStatus := &types.AppInstanceStatus{}
	if structName2, err = readJSONFile(rootRun, structName, AppUUID, appInstanceStatus); err != nil {
		appInfo = appendFailedItem(appInfo, structName, AppUUID, err)
	} else {
		ai = AppInfoItems{ // AppInstanceStatus
			UUID:      AppUUID,
			Name:      appInstanceStatus.DomainName,
			Exist:     true,
			Activated: boolToTriState(appInstanceStatus.Activated),
			State:     appInstanceStatus.State.String(),
			DNidNode:  boolToTriState(appInstanceStatus.IsDesignatedNodeID),
		}
		appInfo = append(appInfo, OrderedAppInfoItem{Key: structName2, Value: ai})
	}

	// 15) Get the DomainConfig for the App from zedmanager, it may not exist, then return here
	structName = "zedmanager-DomainConfig"
	domainConfig := &types.DomainConfig{}
	if structName2, err = readJSONFile(rootRun, structName, AppUUID, domainConfig); err != nil {
		return addHostnameAppInfo(hostname, appendFailedItem(appInfo, structName, AppUUID, err))
	}
	ai = AppInfoItems{ // DomainConfig
		UUID:      AppUUID,
		Name:      domainConfig.DisplayName,
		Exist:     true,
		Activated: boolToTriState(domainConfig.Activate),
		DNidNode:  boolToTriState(domainConfig.IsDNidNode),
		Content:   fmt.Sprintf("AppNum %d, KubeImage %s", domainConfig.AppNum, domainConfig.KubeImageName),
	}
	appInfo = append(appInfo, OrderedAppInfoItem{Key: structName2, Value: ai})

	// 16) Get the DomainStatus from domainmgr, it may not exist
	structName = "domainmgr-DomainStatus"
	domainStatus := &types.DomainStatus{}
	if structName2, err = readJSONFile(rootRun, structName, AppUUID, domainStatus); err != nil {
		appInfo = appendFailedItem(appInfo, structName, AppUUID, err)
	} else {
		ai = AppInfoItems{ // DomainStatus
			UUID:      AppUUID,
			Name:      domainStatus.DisplayName,
			Exist:     true,
			Activated: boolToTriState(domainStatus.Activated),
			State:     domainStatus.State.String(),
			DNidNode:  boolToTriState(domainStatus.IsDNidNode),
			Content:   fmt.Sprintf("AppNum %d, NodeName %s", domainStatus.AppNum, domainStatus.NodeName),
		}
		appInfo = append(appInfo, OrderedAppInfoItem{Key: structName2, Value: ai})
	}

	// 17) Get the DomainMetric from domainmgr, it may not exist
	structName = "domainmgr-DomainMetric"
	domainMetric := &types.DomainMetric{}
	if structName2, err = readJSONFile(rootRun, structName, AppUUID, domainMetric); err != nil {
		appInfo = appendFailedItem(appInfo, structName, AppUUID, err)
	} else {
		ai = AppInfoItems{ // DomainMetric
			UUID:      AppUUID,
			Exist:     true,
			Activated: boolToTriState(domainMetric.Activated),
			Content:   fmt.Sprintf("Alloc Mem %d, Percent %f, Last updated %v", domainMetric.AllocatedMB, domainMetric.UsedMemoryPercent, domainMetric.LastHeard.UTC().Format(time.RFC3339)),
		}
		appInfo = append(appInfo, OrderedAppInfoItem{Key: structName2, Value: ai})
	}

	// 18) Get the AppDiskMetric from volumemgr, it may not exist
	structName = "volumemgr-AppDiskMetric"
	for _, volumeID := range appInternal.AppVolumes {
		appDiskMetric := &types.AppDiskMetric{}
		if structName2, err = readJSONFile(rootRun, structName, volumeID.VolumeID, appDiskMetric); err != nil {
			appInfo = appendFailedItem(appInfo, structName, volumeID.VolumeID, err)
			continue
		}
		ai = AppInfoItems{ // AppDiskMetric
			UUID:    volumeID.VolumeID,
			Name:    "Disk Path: " + appDiskMetric.DiskPath,
			Exist:   true,
			State:   "Disk Type: " + appDiskMetric.DiskType,
			Content: fmt.Sprintf("Provisioned bytes: %v, used bytes: %v, Dirty: %v", appDiskMetric.ProvisionedBytes, appDiskMetric.UsedBytes, appDiskMetric.Dirty),
		}
		appInfo = append(appInfo, OrderedAppInfoItem{Key: structName2, Value: ai})
	}

	return addHostnameAppInfo(hostname, appInfo)
}

// readJSONFile reads a JSON file and unmarshals its content into the provided struct.
func readJSONFile(rootRun, structName, itemUUID string, v interface{}) (string, error) {

	filePath, err := getPath(rootRun, structName, itemUUID, ".json")
	if err != nil {
		return "", fmt.Errorf("file does not exist for  %s, uuid %s", structName, itemUUID)
	}

	// Read the file content
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %v", err)
	}

	// Unmarshal the JSON content into the provided struct
	if err := json.Unmarshal(data, v); err != nil {
		return "", fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	if itemUUID == "global" {
		return structName, nil
	}

	first5Chars := itemUUID
	if len(itemUUID) > 5 {
		first5Chars = itemUUID[:5]
	} else {
		return "", fmt.Errorf("UUID is too short: %s", itemUUID)
	}
	result := fmt.Sprintf("%s-%s", structName, first5Chars)

	return result, nil
}

// getPath constructs the path based on the given input strings.
func getPath(rootRun, input, uuidString, suffixStr string) (string, error) {
	parts := strings.Split(input, "-")
	if len(parts) != 2 {
		return "", fmt.Errorf("input string must be in the format 'string1-string2'")
	}
	dirPath := filepath.Join(rootRun, parts[0], parts[1])
	files, err := os.ReadDir(dirPath)
	if err != nil {
		return "", fmt.Errorf("error reading directory: %v", err)
	}

	// the file name format could be '<uuid>.json' or '<uuid#0>.json' or '<uuid-pvc-0>.json', etc.
	// we just need to match one of them.
	for _, file := range files {
		if !file.IsDir() {
			fileName := file.Name()
			if strings.HasPrefix(fileName, uuidString) && strings.HasSuffix(fileName, suffixStr) {
				return filepath.Join(dirPath, fileName), nil
			}
		}
	}
	return "", fmt.Errorf("no file found with prefix '%s' and suffix '%s' in directory '%s'", uuidString, suffixStr, dirPath)
}

func appendFailedItem(appInfo []OrderedAppInfoItem, structName, UUID string, err error) []OrderedAppInfoItem {
	ai := AppInfoItems{
		UUID:   UUID,
		Exist:  false,
		Errors: fmt.Sprintf("%s: Not found for: %s, %v", structName, UUID, err),
	}
	return append(appInfo, OrderedAppInfoItem{Key: structName, Value: ai})
}

func addHostnameAppInfo(hostname string, appInfo []OrderedAppInfoItem) AppTrackerInfo {
	af := AppTrackerInfo{
		Hostname:    hostname,
		CollectTime: time.Now().UTC().Format(time.RFC3339),
		AppInfo:     appInfo,
	}
	return af
}

// tail the last 10 lines of k3s-install.log file in kubelog directory
func getTailOfK3sInstallLog(persistKubelog string) (string, error) {
	filePath := filepath.Join(persistKubelog, "k3s-install.log")
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	// Read the file content
	content, err := io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("error reading file: %v", err)
	}

	// Split the content into lines
	lines := strings.Split(string(content), "\n")

	// Get the last n lines
	start := len(lines) - 10
	if start < 0 {
		start = 0
	}
	lastLines := lines[start:]

	// Join the lines into a single string
	result := strings.Join(lastLines, "\n")
	return result, nil
}

// boolToTriState - convert bool to TriState
func boolToTriState(b bool) LocalTriState {
	if b {
		return LocalTriState(types.TS_ENABLED)
	}
	return LocalTriState(types.TS_DISABLED)
}

// MarshalJSON - convert TriState to JSON formatted bytes
// the type definition and MarshalJSON need to be in the same package
func (t LocalTriState) MarshalJSON() ([]byte, error) {
	// Use the existing types.FormatTriState() function to get the string representation
	s := types.FormatTriState(types.TriState(t))
	return json.Marshal(s)
}
