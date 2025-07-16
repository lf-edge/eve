// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest/constants"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/logger"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// gatherLogsFromAllDevices retrieves device logs from all known EVE devices
// and stores them as artifact files under the test artifact directory.
//
// For each device, logs are fetched via Adam with a bounded timeout and
// written into a file named "<device-name>.log". Failures for individual
// devices are logged but do not abort processing of other devices.
func (th *TestHarness) gatherLogsFromAllDevices() {
	th.log.Infof("Gathering logs from all EVE devices...")
	th.devicesM.Lock()
	defer th.devicesM.Unlock()

	for _, dev := range th.devices {
		filePath := filepath.Join(
			th.test.artifactDir, fmt.Sprintf("%s.log", dev.name))

		outFile, err := os.Create(filePath)
		if err != nil {
			th.log.Errorf(
				"Unable to create log artifact file %q for device %q: %v",
				filePath, dev.name, err)
			continue
		}

		ctx, cancel := context.WithTimeout(th.ctx, gatherLogsTimeout)
		logWriter := &logger.PlainDeviceLogFile{OutFile: outFile}
		err = th.adamClient.IterateDeviceLogs(ctx, dev.ID, nil, logWriter, false)
		cancel()
		if err != nil {
			th.log.Errorf(
				"Failed to retrieve logs for device %q: %v",
				dev.name, err)
		}

		if err = outFile.Close(); err != nil {
			th.log.Errorf(
				"Failed to close log artifact file %q for device %q: %v",
				filePath, dev.name, err)
		}
	}
}

// gatherConsoleOutputFromAllDevices retrieves the current console output
// from all known EVE devices via the broker and stores it as artifact files.
//
// For each device, console output is requested with a bounded timeout and
// written into a file named "<device-name>.console". Failures are logged per
// device and do not interrupt processing of remaining devices.
func (th *TestHarness) gatherConsoleOutputFromAllDevices() {
	th.log.Infof("Gathering console output from all EVE devices...")
	th.devicesM.Lock()
	defer th.devicesM.Unlock()

	for _, dev := range th.devices {
		ctx, cancel := context.WithTimeout(
			th.ctx, brokerGetConsoleOutputTimeout)

		resp, err := th.brokerClient.GetDeviceConsoleOutput(
			ctx,
			&api.DeviceControlRequest{
				ClientId:   th.brokerClientID,
				DeviceName: dev.name,
			},
		)
		cancel()

		if err != nil {
			th.log.Errorf(
				"Failed to retrieve console output for device %q: %v",
				dev.name, err)
			continue
		}

		filePath := filepath.Join(
			th.test.artifactDir, fmt.Sprintf("%s.console", dev.name))

		if err = os.WriteFile(filePath,
			[]byte(resp.ConsoleOutput), 0666); err != nil {
			th.log.Errorf(
				"Failed to write console artifact file %q for device %q: %v",
				filePath, dev.name, err)
		}
	}
}

type infoMsgFileIterator struct {
	outFile io.Writer
}

func (w *infoMsgFileIterator) Iterate(msg *eveinfo.ZInfoMsg) (bool, error) {
	_, err := fmt.Fprintf(w.outFile, "%s\n\n", msg.String())
	return false, err
}

// gatherInfoMsgsFromAllDevices retrieves published informational messages
// from all known EVE devices and stores them as artifact files under the
// test artifact directory.
//
// For each device, info messages are fetched via Adam with a bounded timeout
// and written into a file named "<device-name>.info". Errors encountered for
// individual devices are logged but do not prevent processing of others.
func (th *TestHarness) gatherInfoMsgsFromAllDevices() {
	th.log.Infof("Gathering published info messages from all EVE devices...")
	th.devicesM.Lock()
	defer th.devicesM.Unlock()

	for _, dev := range th.devices {
		filePath := filepath.Join(
			th.test.artifactDir, fmt.Sprintf("%s.info", dev.name))

		outFile, err := os.Create(filePath)
		if err != nil {
			th.log.Errorf(
				"Unable to create artifact file %q with info messages for device %q: %v",
				filePath, dev.name, err)
			continue
		}
		iterator := &infoMsgFileIterator{outFile: outFile}

		ctx, cancel := context.WithTimeout(th.ctx, gatherInfoMsgsTimeout)
		err = th.adamClient.IterateDeviceInfoMsgs(ctx, dev.ID, nil, iterator, false)
		cancel()

		if err != nil {
			th.log.Errorf(
				"Failed to retrieve info messages for device %q: %v",
				dev.name, err)
		}

		if err = outFile.Close(); err != nil {
			th.log.Errorf(
				"Failed to close artifact file %q with info messages for device %q: %v",
				filePath, dev.name, err)
		}
	}
}

// Try to obtain collect-info tarball from every EVE device.
func (th *TestHarness) collectInfoFromAllDevices() {
	var wg sync.WaitGroup
	th.log.Infof("Trying to obtain collect-info tarball from every EVE device...")

	const maxAttempts = 3

	th.devicesM.Lock()
	for _, dev := range th.devices {
		wg.Add(1)
		go func(devName string) {
			defer wg.Done()

			var lastErr error
			for attempt := 1; attempt <= maxAttempts; attempt++ {
				ctx, cancel := context.WithTimeout(th.ctx, collectInfoTimeout)
				_, err := th.collectInfoFromDevice(ctx, devName)
				cancel()

				if err == nil {
					if attempt > 1 {
						th.log.Infof(
							"Successfully collected info from device %q on attempt %d/%d",
							devName, attempt, maxAttempts,
						)
					}
					return
				}

				lastErr = err
				th.log.Warnf(
					"Failed to collect info from device %q (attempt %d/%d): %v",
					devName, attempt, maxAttempts, err,
				)
			}

			th.log.Errorf(
				"Giving up collecting info from device %q after %d attempts: %v",
				devName, maxAttempts, lastErr,
			)
		}(dev.name)
	}
	th.devicesM.Unlock()

	wg.Wait()
}

// Try to obtain collect-info tarball from the given EVE device.
func (th *TestHarness) collectInfoFromDevice(
	ctx context.Context, devName string) (filePath string, err error) {
	// Run collect-info.sh and capture its output.
	ciStdout := logger.LogWriter{
		Log:    th.log,
		Level:  logrus.DebugLevel,
		Prefix: fmt.Sprintf("collect-info (%s): ", devName),
	}
	// Expect collect-info.sh to emit stdout at least once every 5 minutes.
	// The relatively long timeout accounts for copying /sys/fs/cgroup/memory,
	// which can be slow due to the large number of cgroups (notably on eve-k).
	stdoutWatchdogTimeout := 5 * time.Minute
	err = th.runScriptOnEVEOverSSH(ctx,
		devName, "collect-info.sh", ciStdout, nil, stdoutWatchdogTimeout)
	if err != nil {
		err = fmt.Errorf("collect-info.sh failed on device %q: %v",
			devName, err)
		return "", err
	}

	// Prepare output file for the collect-info artifact.
	filePath = filepath.Join(th.test.artifactDir,
		fmt.Sprintf("eve-info-%s.tar", devName),
	)
	outFile, err := os.Create(filePath)
	if err != nil {
		err = fmt.Errorf("failed to create collect-info artifact for device %q: %v",
			devName, err)
		return "", err
	}
	defer outFile.Close()

	// Archive the collected info (alongside any other previously collected infos)
	// and stream it to the artifact file.
	// We should see a constant stream of tar-ed data coming.
	stdoutWatchdogTimeout = 20 * time.Second
	err = th.runScriptOnEVEOverSSH(ctx,
		devName, "tar -C /persist -cf - eve-info", outFile, nil, stdoutWatchdogTimeout)
	if err != nil {
		err = fmt.Errorf("failed to archive collect-info from device %q: %v",
			devName, err)
		return "", err
	}

	th.log.Infof("Received collect-info tarball from EVE device %q", devName)
	return filePath, nil
}

// collectCoverageFromAllDevices sends SIGUSR2 to zedbox on every known EVE
// device and SCP-copies the resulting .covcounters/.covmeta files from
// /persist/coverage into <test.artifactDir>/coverage/<device-name>/.
//
// Because .covcounters filenames contain a pid and nanosecond timestamp they
// are unique across runs; all collections for a device accumulate in one flat
// subdirectory and can be merged later with "go tool covdata merge".
//
// Failures for individual devices are logged but do not abort other devices.
func (th *TestHarness) collectCoverageFromAllDevices() {
	th.log.Infof("Collecting coverage data from all EVE devices...")
	var wg sync.WaitGroup

	th.devicesM.Lock()
	for _, dev := range th.devices {
		wg.Add(1)
		devName := dev.name
		go func(devName string) {
			defer wg.Done()
			th.collectCoverageFromDevice(th.ctx, devName)
		}(devName)
	}
	th.devicesM.Unlock()

	wg.Wait()
}

// collectCoverageFromDevice signals zedbox on the named device to write
// coverage counters, waits for a new .covcounters file to appear, then
// SCP-copies all files from /persist/coverage into
// <test.artifactDir>/coverage/<devName>/.
//
// The function is a no-op when EVETEST_COLLECT_COVERAGE or
// EVETEST_COLLECT_ARTIFACTS is unset. The provided context is wrapped with
// collectCoverageTimeout so the caller does not need to manage the deadline.
//
// Detection works by counting .covcounters files before sending SIGUSR2 and
// polling until the count increases. If the before-count snapshot fails, a
// 3-second fallback sleep is used instead.
func (th *TestHarness) collectCoverageFromDevice(ctx context.Context, devName string) {
	if !viper.GetBool(constants.CollectCoverageEnv) ||
		viper.GetString(constants.ExternalArtifactDirEnv) == "" {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, collectCoverageTimeout)
	defer cancel()
	const eveCoverageDir = "/persist/coverage"

	th.log.Infof("Collecting coverage from device %q...", devName)

	// Snapshot the number of .covcounters files before signalling so we can
	// detect the new file by a count increase.
	var countBuf bytes.Buffer
	countErr := th.runScriptOnEVEOverSSH(ctx, devName,
		"ls "+eveCoverageDir+"/covcounters.* 2>/dev/null | wc -l",
		&countBuf, nil, 0)
	beforeCount := strings.TrimSpace(countBuf.String())

	// Signal zedbox to flush in-memory coverage counters to /persist/coverage.
	if err := th.runScriptOnEVEOverSSH(ctx, devName,
		"kill -USR2 $(pgrep -x zedbox)", nil, nil, 0); err != nil {
		th.log.Warnf("SIGUSR2 to zedbox on device %q failed: %v; "+
			"coverage may be incomplete", devName, err)
	}

	// Wait for a new covcounters file to appear.
	if countErr != nil || beforeCount == "" {
		th.log.Warnf("Failed to snapshot coverage file count on device %q (%v); "+
			"using fixed 3s sleep", devName, countErr)
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	} else {
		const pollInterval = 5 * time.Second
		const waitTimeout = 30 * time.Second
		pollCmd := fmt.Sprintf(
			`[ $(ls %s/covcounters.* 2>/dev/null | wc -l) -gt %s ]`,
			eveCoverageDir, beforeCount)
		deadline := time.Now().Add(waitTimeout)
		for {
			if th.runScriptOnEVEOverSSH(ctx, devName, pollCmd, nil, nil, 0) == nil {
				break
			}
			if time.Now().After(deadline) {
				th.log.Warnf("No new coverage files on device %q after %v; "+
					"proceeding with whatever was written", devName, waitTimeout)
				break
			}
			th.log.Debugf("Waiting for coverage files on device %q...", devName)
			select {
			case <-ctx.Done():
				th.log.Warnf("Context cancelled while waiting for "+
					"coverage files on device %q", devName)
				return
			case <-time.After(pollInterval):
			}
		}
	}

	// Create the per-device output directory.
	localDir := filepath.Join(th.test.artifactDir, "coverage", devName)
	if err := os.MkdirAll(localDir, 0o755); err != nil {
		th.log.Errorf("Failed to create coverage output directory: %v", err)
		return
	}

	// SCP the coverage files from the device. Appending "/." to the remote path
	// copies the directory contents directly into localDir rather than creating
	// a "coverage" subdirectory inside it.
	if err := th.scpFromEVE(ctx, devName,
		eveCoverageDir+"/.", localDir, true); err != nil {
		th.log.Warnf("Failed to copy coverage files from device %q: %v",
			devName, err)
		return
	}

	th.log.Infof("Collected coverage files from device %q to %q", devName, localDir)
}
