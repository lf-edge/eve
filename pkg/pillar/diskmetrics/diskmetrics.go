// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diskmetrics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const qemuExecTimeout = 2 * time.Minute

// qemuExecLongTimeout is a long timeout for command executions in separate worker thread that don't interfere with the watchdog
const qemuExecLongTimeout = 1000 * time.Second

// qemuExecUltraLongTimeout is a long timeout for command executions in separate worker thread that take especially long
const qemuExecUltraLongTimeout = 120 * time.Hour

func GetImgInfo(log *base.LogObject, diskfile string) (*types.ImgInfo, error) {
	var imgInfo types.ImgInfo

	if _, err := os.Stat(diskfile); err != nil {
		return nil, err
	}
	output, err := base.Exec(log, "/usr/bin/qemu-img", "info", "-U", "--output=json",
		diskfile).WithUnlimitedTimeout(qemuExecLongTimeout).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("qemu-img failed: %s, %s\n",
			err, output)
		return nil, errors.New(errStr)
	}
	if err := json.Unmarshal(output, &imgInfo); err != nil {
		return nil, err
	}
	return &imgInfo, nil
}

// GetDiskVirtualSize - returns VirtualSize of the image
func GetDiskVirtualSize(log *base.LogObject, diskfile string) (uint64, error) {
	imgInfo, err := GetImgInfo(log, diskfile)
	if err != nil {
		return 0, err
	}
	return imgInfo.VirtualSize, nil
}

// CheckResizeDisk returns size and indicates do we need to resize disk to be at least maxsizebytes
func CheckResizeDisk(log *base.LogObject, diskfile string, maxsizebytes uint64) (uint64, bool, error) {
	vSize, err := GetDiskVirtualSize(log, diskfile)
	if err != nil {
		return 0, false, err
	}
	if vSize > maxsizebytes {
		log.Warnf("Virtual size (%d) of provided volume(%s) is larger than provided MaxVolSize (%d). "+
			"Will use virtual size.", vSize, diskfile, maxsizebytes)
		return vSize, false, nil
	}
	return maxsizebytes, vSize != maxsizebytes, nil
}

// ResizeImg calls qemu-img to resize disk file to new size
func ResizeImg(ctx context.Context, log *base.LogObject, diskfile string, newsize uint64) error {
	if _, err := os.Stat(diskfile); err != nil {
		return err
	}
	output, err := base.Exec(log, "/usr/bin/qemu-img", "resize", diskfile,
		strconv.FormatUint(newsize, 10)).WithContext(ctx).WithUnlimitedTimeout(qemuExecLongTimeout).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("qemu-img failed: %s, %s\n",
			err, output)
		return errors.New(errStr)
	}
	return nil
}

// CreateImg creates empty diskfile with defined format and size
func CreateImg(ctx context.Context, log *base.LogObject, diskfile string, format string, size uint64) error {
	output, err := base.Exec(log, "/usr/bin/qemu-img", "create", "-f", format, diskfile,
		strconv.FormatUint(size, 10)).WithContext(ctx).WithUnlimitedTimeout(qemuExecLongTimeout).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("qemu-img failed: %s, %s\n",
			err, output)
		return errors.New(errStr)
	}
	return nil
}

// RolloutImgToBlock do conversion of diskfile to outputFile with defined format
func RolloutImgToBlock(ctx context.Context, log *base.LogObject, diskfile, outputFile, outputFormat string) error {
	if _, err := os.Stat(diskfile); err != nil {
		return err
	}
	// writeback cache instead of default unsafe, out of order enabled, skip file creation
	// Timeout 2 hours
	args := []string{"convert", "--target-is-zero", "-t", "writeback", "-W", "-n", "-O", outputFormat, diskfile, outputFile}
	output, err := base.Exec(log, "/usr/bin/qemu-img", args...).WithContext(ctx).WithUnlimitedTimeout(qemuExecUltraLongTimeout).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("qemu-img failed: %s, %s\n",
			err, output)
		return errors.New(errStr)
	}
	return nil
}

// CreateSnapshot creates snapshot of diskfile with defined format and size
func CreateSnapshot(ctx context.Context, log *base.LogObject, diskfile, snapshotName string) error {
	// Command line should be:
	// `qemu-img snapshot -c snapshot_name /path/to/base_image.qcow2`
	if _, err := os.Stat(diskfile); err != nil {
		return err
	}
	cmdBin := "/usr/bin/qemu-img"
	cmdArgs := []string{"snapshot", "-c", snapshotName, diskfile}
	log.Noticef("CreateSnapshot: %s %s", cmdBin, strings.Join(cmdArgs, " "))
	output, err := base.Exec(log, cmdBin, cmdArgs...).WithContext(ctx).WithLimitedTimeout(qemuExecTimeout).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("qemu-img failed: %s, %s\n", err, output)
		return errors.New(errStr)
	}
	return nil
}

// ApplySnapshot applies snapshot to diskfile
func ApplySnapshot(ctx context.Context, log *base.LogObject, diskfile, snapshotName string) error {
	// Command line should be:
	// `qemu-img snapshot -a snapshot_name /path/to/base_image.qcow2`
	if _, err := os.Stat(diskfile); err != nil {
		return err
	}
	cmdBin := "/usr/bin/qemu-img"
	cmdArgs := []string{"snapshot", "-a", snapshotName, diskfile}
	log.Noticef("ApplySnapshot: %s %s", cmdBin, strings.Join(cmdArgs, " "))
	output, err := base.Exec(log, cmdBin, cmdArgs...).WithContext(ctx).WithLimitedTimeout(qemuExecTimeout).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("qemu-img failed: %s, %s\n", err, output)
		return errors.New(errStr)
	}
	return nil
}

// DeleteSnapshot deletes snapshot with a given name created for a given diskfile
func DeleteSnapshot(ctx context.Context, log *base.LogObject, diskfile, snapshotName string) error {
	// Command line should be:
	// `qemu-img snapshot -d snapshot_name /path/to/base_image.qcow2`
	cmdBin := "/usr/bin/qemu-img"
	cmdArgs := []string{"snapshot", "-d", snapshotName, diskfile}
	log.Noticef("DeleteSnapshot: %s %s", cmdBin, strings.Join(cmdArgs, " "))
	output, err := base.Exec(log, cmdBin, cmdArgs...).WithContext(ctx).WithLimitedTimeout(qemuExecTimeout).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("qemu-img failed: %s, %s\n", err, output)
		return errors.New(errStr)
	}
	return nil
}
