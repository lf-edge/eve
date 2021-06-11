// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zfs

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/vault"
)

var (
	zfsPath = []string{"/hostfs", "zfs"}
)

//DestroyDataset removes dataset from zfs
func DestroyDataset(log *base.LogObject, dataset string) (string, error) {
	args := append(zfsPath, "destroy", dataset)
	stdoutStderr, err := base.Exec(log, vault.ZfsPath, args...).CombinedOutput()
	if err != nil {
		return string(stdoutStderr), err
	}
	return string(stdoutStderr), nil
}

//GetDatasetOptions get dataset options from zfs
//will return error if not exists
func GetDatasetOptions(log *base.LogObject, dataset string) (map[string]string, error) {
	args := append(zfsPath, "get", "-Hp", "-o", "property,value", "all", dataset)
	stdoutStderr, err := base.Exec(log, vault.ZfsPath, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("cannot obtain options of %s, output=%s, error=%s",
			dataset, stdoutStderr, err)
	}
	processedValues := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(stdoutStderr)))
	for scanner.Scan() {
		err = nil
		currentLine := scanner.Text()
		split := strings.Split(currentLine, "\t")
		if len(split) < 2 {
			return nil, fmt.Errorf("cannot process line %s: not in format <key>\\t<value>", currentLine)
		}
		processedValues[split[0]] = split[1]
	}
	return processedValues, nil
}

//GetDatasetOption get dataset option value from zfs
//will return error if not exists
func GetDatasetOption(log *base.LogObject, dataset string, option string) (string, error) {
	args := append(zfsPath, "get", "-Hp", "-o", "value", option, dataset)
	stdoutStderr, err := base.Exec(log, vault.ZfsPath, args...).CombinedOutput()
	if err != nil {
		return string(stdoutStderr), err
	}
	return strings.TrimSpace(string(stdoutStderr)), nil
}

//CreateVolumeDataset creates dataset of zvol type in zfs
func CreateVolumeDataset(log *base.LogObject, dataset string, size uint64, compression string) (string, error) {
	args := append(zfsPath, "create", "-p",
		"-V", strconv.FormatUint(size, 10),
		"-o", "volmode=dev",
		"-o", fmt.Sprintf("compression=%s", compression),
		dataset)
	stdoutStderr, err := base.Exec(log, vault.ZfsPath, args...).CombinedOutput()
	if err != nil {
		return string(stdoutStderr), err
	}
	return string(stdoutStderr), nil
}

//GetVolumesInDataset obtains volumes list from dataset
func GetVolumesInDataset(log *base.LogObject, dataset string) ([]string, error) {
	args := append(zfsPath, "list", "-Hr",
		"-o", "name",
		"-t", "volume",
		dataset)
	stdoutStderr, err := base.Exec(log, vault.ZfsPath, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("GetVolumesInDataset: output=%s error=%s", stdoutStderr, err)
	}
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(stdoutStderr))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

//GetDatasetByDevice returns dataset for provided device path
func GetDatasetByDevice(device string) string {
	if !strings.HasPrefix(device, types.ZVolDevicePrefix) {
		return ""
	}
	return strings.TrimLeft(strings.TrimLeft(device, types.ZVolDevicePrefix), "/")
}

//GetZVolDeviceByDataset return path to device for provided dataset
func GetZVolDeviceByDataset(dataset string) string {
	return filepath.Join(types.ZVolDevicePrefix, dataset)
}

//GetZFSVolumeInfo provides information for zfs device
func GetZFSVolumeInfo(log *base.LogObject, device string) (*types.ImgInfo, error) {
	imgInfo := types.ImgInfo{
		Format:    "raw",
		Filename:  device,
		DirtyFlag: false,
	}
	dataset := GetDatasetByDevice(device)
	if dataset == "" {
		return nil, fmt.Errorf("GetDatasetByDevice returns empty for device: %s",
			device)
	}
	referenced, err := GetDatasetOption(log, dataset, "referenced")
	if err != nil {
		return nil, fmt.Errorf("GetZFSVolumeInfo GetDatasetOption failed: %s", err)
	}
	imgInfo.ActualSize, err = strconv.ParseUint(referenced, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("GetZFSVolumeInfo: failed to parse referenced: %s", err)
	}
	volSize, err := GetDatasetOption(log, dataset, "volsize")
	if err != nil {
		return nil, fmt.Errorf("GetZFSVolumeInfo GetDatasetOption failed: %s", err)
	}
	imgInfo.VirtualSize, err = strconv.ParseUint(volSize, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("GetZFSVolumeInfo: failed to parse volsize: %s", err)
	}
	volBlockSize, err := GetDatasetOption(log, dataset, "volblocksize")
	if err != nil {
		return nil, fmt.Errorf("GetZFSVolumeInfo GetDatasetOption failed: %s", err)
	}
	imgInfo.ClusterSize, err = strconv.ParseUint(volBlockSize, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("GetZFSVolumeInfo: failed to parse volblocksize: %s", err)
	}
	return &imgInfo, nil
}
