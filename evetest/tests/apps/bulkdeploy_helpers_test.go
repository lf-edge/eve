// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// What the bulk-deployment test builds and drives: the churn a scale-test
// tool applies to the containers of a real deployment, the real workload
// images it can deploy instead of the test container, and a wait for
// RUNNING that tolerates a starved control plane.

package apps_test

import (
	"fmt"
	"strings"
	"sync"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
	uuid "github.com/satori/go.uuid"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
)

// appChurnScript, run inside a container over SSH, starts a detached loop
// that twice a second adds a fresh IP address on the app's VIF, sends one
// ARP request from it and prints a burst of lines to the container's
// console, then removes the address again. On a switch NI every such ARP
// packet reaches nistate's packet capture as a changed IP assignment of
// the VIF, which zedrouter and zedagent then process and log, and every
// console line goes through newlogd, the way a chatty workload's output
// does. The first %d is the per-app index that keeps the addresses distinct
// across apps (10.99.0.0/16 is outside every subnet the test uses); the
// second is the number of console lines per step.
const appChurnScript = `
nohup setsid sh -c '
idx=$1; lines=$2; i=0
while true; do
  i=$((i+1)); n=$((i %% 200 + 2)); a=10.99.$idx.$n
  ip addr add $a/24 dev eth0 2>/dev/null
  ping -c1 -W1 -I $a 10.99.$idx.1 >/dev/null 2>&1
  j=0
  while [ $j -lt $lines ]; do
    j=$((j+1))
    echo "bulk-churn app=$idx step=$i line=$j addr=$a $(date +%%T)" > /proc/1/fd/1 2>/dev/null
  done
  sleep 0.5
  ip addr del $a/24 dev eth0 2>/dev/null
done' churn %d %d >/dev/null 2>&1 </dev/null &
echo churn-started
`

// startAppChurn starts appChurnScript, with logLines console lines per
// step, in every listed container, in parallel, retrying each app's SSH
// session for up to perAppTimeout (the app reports RUNNING before its sshd
// is reachable). It returns one error per app that could not be reached,
// naming the app.
func startAppChurn(device *evetest.EdgeDevice, appUUIDs []uuid.UUID,
	perAppTimeout time.Duration, logLines int) []error {
	const (
		sshTimeout = 30 * time.Second
		retryDelay = 10 * time.Second
	)
	log := evetest.Logger()
	var mu sync.Mutex
	var errs []error
	evetest.RunParallel(len(appUUIDs), func(i int) {
		script := fmt.Sprintf(appChurnScript, i, logLines)
		deadline := time.Now().Add(perAppTimeout)
		var lastErr error
		for {
			stdout, _, err := device.RunShellScriptInsideApp(appUUIDs[i], appAuth,
				script, sshTimeout, 0)
			if err == nil && strings.Contains(stdout, "churn-started") {
				return
			}
			if err == nil {
				err = fmt.Errorf("unexpected output %q", strings.TrimSpace(stdout))
			}
			lastErr = err
			if time.Now().After(deadline) {
				break
			}
			time.Sleep(retryDelay)
		}
		log.Warnf("App %s: churn not started: %v", appUUIDs[i], lastErr)
		mu.Lock()
		errs = append(errs, fmt.Errorf("app %s: %w", appUUIDs[i], lastErr))
		mu.Unlock()
	})
	return errs
}

// waitAppsRunning waits, in parallel, until every listed application reports
// RUNNING -- with a boot time after notBefore, so that after a device reboot
// an app's RUNNING history from before it cannot pass for the new run (a
// zero notBefore accepts any boot time) -- and returns one error per
// application that reported ERROR or did not make it within timeout.
//
// Unlike EdgeDevice.WaitUntilAppIsRunning it applies no download-stall
// heuristic: a deployment that starves EVE's own services legitimately sits
// at 0% for minutes on end, and observing that is what this test is for.
func waitAppsRunning(device *evetest.EdgeDevice, appUUIDs []uuid.UUID,
	notBefore time.Time, timeout time.Duration) []error {
	log := evetest.Logger()
	var mu sync.Mutex
	var errs []error
	fail := func(err error) {
		mu.Lock()
		errs = append(errs, err)
		mu.Unlock()
	}
	evetest.RunParallel(len(appUUIDs), func(i int) {
		appUUID := appUUIDs[i]
		updates, stop := device.WatchAppInfo(appUUID)
		defer stop()
		deadline := time.NewTimer(timeout)
		defer deadline.Stop()
		lastState := eveinfo.ZSwState_INVALID
		// check reports whether info settles the wait, and with what.
		check := func(info *eveinfo.ZInfoApp) (done bool, err error) {
			if info == nil {
				return false, nil
			}
			if info.GetState() != lastState {
				log.Infof("App %q (%s) state changed to %s",
					appUUID, info.GetAppName(), info.GetState())
				lastState = info.GetState()
			}
			switch info.GetState() {
			case eveinfo.ZSwState_ERROR:
				descs := make([]string, 0, len(info.GetAppErr()))
				for _, appErr := range info.GetAppErr() {
					descs = append(descs, appErr.GetDescription())
				}
				return true, fmt.Errorf("app %s (%s) is in ERROR state: %s",
					appUUID, info.GetAppName(), strings.Join(descs, "; "))
			case eveinfo.ZSwState_RUNNING:
				bootTime := info.GetBootTime()
				if notBefore.IsZero() ||
					(bootTime != nil && bootTime.AsTime().After(notBefore)) {
					return true, nil
				}
			}
			return false, nil
		}
		if done, err := check(device.GetAppInfo(appUUID)); done {
			if err != nil {
				fail(err)
			}
			return
		}
		for {
			select {
			case info, ok := <-updates:
				if !ok {
					fail(fmt.Errorf("app %s: the info watch was closed", appUUID))
					return
				}
				if done, err := check(info); done {
					if err != nil {
						fail(err)
					}
					return
				}
			case <-deadline.C:
				fail(fmt.Errorf("app %s did not reach RUNNING within %s "+
					"(last state %s)", appUUID, timeout, lastState))
				return
			}
		}
	})
	return errs
}

// describeErrors renders errors one per line for assertion output.
func describeErrors(errs []error) string {
	lines := make([]string, 0, len(errs))
	for _, err := range errs {
		lines = append(lines, err.Error())
	}
	return strings.Join(lines, "\n")
}

// realImage is a published, file-heavy container image with the user-data
// (one KEY=VALUE per line, which EVE turns into the container's environment)
// and the memory it needs to keep running.
type realImage struct {
	name     string
	userData string
	memory   uint64
}

// realImages are the images the bulk-deployment test cycles through when
// asked to deploy real workloads instead of the test container: the kind of
// images a scale test deploys (databases, a search engine, a CI server, a
// web server), each of which unpacks into tens of thousands of files, so
// that the deployment charges the kernel memory for their dentries and
// inodes to EVE's cgroups the way a real deployment does. Every image keeps
// a long-running process by default or with the user-data given here.
var realImages = []realImage{
	{name: "redis:7", memory: 1024 * evetest.MiB},
	{name: "nginx:1.27", memory: 1024 * evetest.MiB},
	{name: "postgres:16", userData: "POSTGRES_PASSWORD=secret\n",
		memory: 1024 * evetest.MiB},
	{name: "mysql:8", userData: "MYSQL_ROOT_PASSWORD=secret\n",
		memory: 1536 * evetest.MiB},
	{name: "mongo:7", memory: 1024 * evetest.MiB},
	{name: "grafana/grafana:11.2.0", memory: 1024 * evetest.MiB},
	{name: "jenkins/jenkins:lts-jdk17", memory: 1536 * evetest.MiB},
	{name: "elasticsearch:8.15.0",
		userData: "discovery.type=single-node\n" +
			"xpack.security.enabled=false\n" +
			"ES_JAVA_OPTS=-Xms512m -Xmx512m\n",
		memory: 2048 * evetest.MiB},
}

// pushedRealImage is a realImage re-served by evetest's local registry.
type pushedRealImage struct {
	realImage
	container evetest.DockerContainer
}

// pushRealImages pulls every realImage into the harness's docker daemon and
// re-serves it from evetest's local registry, so the device pulls them at
// LAN speed and no public registry's rate limit shapes the deployment.
func pushRealImages(t *WithT) []pushedRealImage {
	log := evetest.Logger()
	pushed := make([]pushedRealImage, 0, len(realImages))
	for _, img := range realImages {
		log.Infof("Publishing %s to the local registry", img.name)
		container, err := evetest.PushDockerImageToLocalRegistry(img.name)
		t.Expect(err).ToNot(HaveOccurred(),
			"failed to publish %s to the local registry", img.name)
		pushed = append(pushed, pushedRealImage{realImage: img, container: container})
	}
	return pushed
}
