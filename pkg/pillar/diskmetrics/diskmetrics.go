// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diskmetrics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// qemuExecLongTimeout is a long timeout for command executions in separate worker thread that don't interfere with the watchdog
const qemuExecLongTimeout = 1000 * time.Second

// qemuExecUltraLongTimeout is a long timeout for command executions in separate worker thread that take especially long
const qemuExecUltraLongTimeout = 120 * time.Hour

// qemuSnapshotTimeout bounds one "qemu-img snapshot" command and one check
// of the image, whose time grows with the clusters in use.
const qemuSnapshotTimeout = 1 * time.Hour

// qemuImgBin and qemuImgLockWait are variables so that tests can replace the
// tool and do without the wait.
var (
	qemuImgBin = "/usr/bin/qemu-img"
	// qemuImgLockWait is how long a check waits before it is tried again.
	qemuImgLockWait = 5 * time.Second
)

// ErrImageNotVerified is returned when "qemu-img check" did not find a disk
// image consistent and could not repair it, or could not be run at all. A VM
// must not run on such an image.
var ErrImageNotVerified = errors.New("disk image could not be verified as consistent")

// GetImgInfo returns the ImgInfo structure from qemu-img info
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

// GetDiskActualSize - returns ActualSize of the image
// following github.com/qemu/qemu/docs/tools/qemu-img.rst:
// "How much space the image file occupies on the host file system" (current size possibly thin)
func GetDiskActualSize(log *base.LogObject, diskfile string) (uint64, error) {
	imgInfo, err := GetImgInfo(log, diskfile)
	if err != nil {
		return 0, err
	}
	return imgInfo.ActualSize, nil
}

// GetDiskVirtualSize - returns VirtualSize of the image
// following github.com/qemu/qemu/docs/tools/qemu-img.rst:
// "The size of the guest disk" (max size)
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

// CreateSnapshot creates a snapshot of diskfile. See snapshotCmd for the
// errors.
func CreateSnapshot(ctx context.Context, log *base.LogObject, diskfile, snapshotName string) error {
	// Command line should be:
	// `qemu-img snapshot -c snapshot_name /path/to/base_image.qcow2`
	return snapshotCmd(ctx, log, diskfile, "-c", snapshotName, func() (bool, error) {
		return hasSnapshot(ctx, log, diskfile, snapshotName)
	})
}

// ApplySnapshot applies snapshot to diskfile. See snapshotCmd for the errors.
func ApplySnapshot(ctx context.Context, log *base.LogObject, diskfile, snapshotName string) error {
	// Command line should be:
	// `qemu-img snapshot -a snapshot_name /path/to/base_image.qcow2`
	// No done check: nothing in the image tells whether it is on the
	// snapshot, and applying it twice does no harm.
	return snapshotCmd(ctx, log, diskfile, "-a", snapshotName, nil)
}

// DeleteSnapshot deletes snapshot with a given name created for a given
// diskfile. See snapshotCmd for the errors.
func DeleteSnapshot(ctx context.Context, log *base.LogObject, diskfile, snapshotName string) error {
	// Command line should be:
	// `qemu-img snapshot -d snapshot_name /path/to/base_image.qcow2`
	return snapshotCmd(ctx, log, diskfile, "-d", snapshotName, func() (bool, error) {
		present, err := hasSnapshot(ctx, log, diskfile, snapshotName)
		return !present, err
	})
}

// snapshotCmd runs "qemu-img snapshot" with the given flag. A failed attempt
// is followed by a repair of the image and, unless done reports that the
// command got far enough, one more attempt. The image is checked in the end.
// Returns an error wrapping ErrImageNotVerified if the image did not pass a
// check. Any other error of the command leaves the image consistent, in the
// state from before or after it.
func snapshotCmd(ctx context.Context, log *base.LogObject, diskfile, flag, snapshotName string,
	done func() (bool, error)) error {
	if _, err := os.Stat(diskfile); err != nil {
		return err
	}
	cmdErr := runSnapshotCmd(ctx, log, diskfile, flag, snapshotName)
	if cmdErr != nil {
		log.Errorf("snapshotCmd: %s, repairing %s", cmdErr, diskfile)
		if err := checkImg(ctx, log, diskfile, true); err != nil {
			return fmt.Errorf("%w: %s; after: %s", ErrImageNotVerified, err, cmdErr)
		}
		cmdErr = finishSnapshotCmd(ctx, log, diskfile, flag, snapshotName, cmdErr, done)
	}
	if err := VerifyImg(ctx, log, diskfile); err != nil {
		if cmdErr != nil {
			return fmt.Errorf("%w; after: %s", err, cmdErr)
		}
		return err
	}
	if cmdErr != nil {
		return &SoundImageError{Err: cmdErr}
	}
	return nil
}

// VerifyImg checks the image and repairs it if the check finds something.
// Returns an error wrapping ErrImageNotVerified if the image could not be
// repaired or checked.
func VerifyImg(ctx context.Context, log *base.LogObject, diskfile string) error {
	err := checkImg(ctx, log, diskfile, false)
	if err == nil {
		return nil
	}
	log.Errorf("VerifyImg: %s, repairing %s", err, diskfile)
	if err := checkImg(ctx, log, diskfile, true); err != nil {
		return fmt.Errorf("%w: %s", ErrImageNotVerified, err)
	}
	return nil
}

// SoundImageError is the failure of a snapshot command that left an image
// which passed its check.
type SoundImageError struct {
	Err error
}

func (e *SoundImageError) Error() string {
	return e.Err.Error()
}

func (e *SoundImageError) Unwrap() error {
	return e.Err
}

// finishSnapshotCmd decides what a failed command on a repaired image comes
// to: done, to be run once more, or failed.
func finishSnapshotCmd(ctx context.Context, log *base.LogObject, diskfile, flag, snapshotName string,
	cmdErr error, done func() (bool, error)) error {
	if done != nil {
		finished, err := done()
		if err != nil {
			// Running it again blindly could do it twice.
			return fmt.Errorf("%s; cannot tell how far it got: %s", cmdErr, err)
		}
		if finished {
			log.Noticef("finishSnapshotCmd: snapshot %s %s had done its part on %s",
				flag, snapshotName, diskfile)
			return nil
		}
	}
	if err := runSnapshotCmd(ctx, log, diskfile, flag, snapshotName); err != nil {
		return fmt.Errorf("%s; first attempt: %s", err, cmdErr)
	}
	return nil
}

func runSnapshotCmd(ctx context.Context, log *base.LogObject, diskfile, flag, snapshotName string) error {
	cmdArgs := []string{"snapshot", flag, snapshotName, diskfile}
	log.Noticef("runSnapshotCmd: %s %s", qemuImgBin, strings.Join(cmdArgs, " "))
	output, err := base.Exec(log, qemuImgBin, cmdArgs...).WithContext(ctx).
		WithUnlimitedTimeout(qemuSnapshotTimeout).CombinedOutput()
	if err != nil {
		return fmt.Errorf("qemu-img failed: %s, %s", err, tail(output))
	}
	return nil
}

// hasSnapshot reports whether diskfile has an internal snapshot of that name.
func hasSnapshot(ctx context.Context, log *base.LogObject, diskfile, snapshotName string) (bool, error) {
	output, err := base.Exec(log, qemuImgBin, "info", "--output=json", diskfile).WithContext(ctx).
		WithUnlimitedTimeout(qemuExecLongTimeout).CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("qemu-img info failed: %s, %s", err, tail(output))
	}
	var info struct {
		Snapshots []struct {
			Name string `json:"name"`
		} `json:"snapshots"`
	}
	if err := json.Unmarshal(output, &info); err != nil {
		return false, fmt.Errorf("qemu-img info: %s", err)
	}
	for _, snapshot := range info.Snapshots {
		if snapshot.Name == snapshotName {
			return true, nil
		}
	}
	return false, nil
}

// Exit codes of "qemu-img check".
const (
	// qemuImgCheckNotCompleted: the check could not be run, for example
	// because the image is locked.
	qemuImgCheckNotCompleted = 1
	// qemuImgCheckCorrupt: the image is corrupt, after the repair if one
	// was asked for.
	qemuImgCheckCorrupt = 2
	// qemuImgCheckLeaksOnly: leaked clusters and nothing else wrong.
	qemuImgCheckLeaksOnly = 3
)

// qemuImgCheckAttempts is how often a check that could not be run is tried.
// A qemu-img that was killed for taking too long can hold the lock on the
// image a moment longer.
const qemuImgCheckAttempts = 3

// checkImg runs "qemu-img check" on diskfile, with repair if asked to.
// Leaked clusters only waste space and are not an error.
func checkImg(ctx context.Context, log *base.LogObject, diskfile string, repair bool) error {
	cmdArgs := []string{"check"}
	if repair {
		cmdArgs = append(cmdArgs, "-r", "all")
	}
	cmdArgs = append(cmdArgs, diskfile)
	name := "qemu-img " + strings.Join(cmdArgs[:len(cmdArgs)-1], " ")
	for attempt := 1; ; attempt++ {
		log.Noticef("checkImg: %s %s", qemuImgBin, strings.Join(cmdArgs, " "))
		output, err := base.Exec(log, qemuImgBin, cmdArgs...).WithContext(ctx).
			WithUnlimitedTimeout(qemuSnapshotTimeout).CombinedOutput()
		if err == nil {
			return nil
		}
		exitCode := -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		switch {
		case exitCode == qemuImgCheckLeaksOnly:
			log.Warnf("checkImg: %s has leaked clusters: %s", diskfile, tail(output))
			return nil
		case exitCode == qemuImgCheckNotCompleted && attempt < qemuImgCheckAttempts:
			log.Warnf("checkImg: %s could not be run on %s, trying again: %s",
				name, diskfile, tail(output))
			time.Sleep(qemuImgLockWait)
		case exitCode == qemuImgCheckCorrupt:
			return fmt.Errorf("%s reports a corrupt image: %s, %s", name, err, tail(output))
		default:
			return fmt.Errorf("%s could not be run: %s, %s", name, err, tail(output))
		}
	}
}

// tail returns the end of the output of a command: qemu-img check prints one
// line per inconsistency before its summary.
func tail(output []byte) string {
	const limit = 512
	if len(output) > limit {
		output = output[len(output)-limit:]
	}
	return strings.TrimSpace(string(output))
}
