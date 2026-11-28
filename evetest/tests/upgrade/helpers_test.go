// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgrade_test

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
)

const (
	// kubeUpgradeTimeout bounds one UpgradeEVE call when the target runs
	// the kube component upgrade pass, including live engine upgrades of
	// attached Longhorn volumes, before the new partition is marked active.
	kubeUpgradeTimeout = 60 * time.Minute
	// kubeConvergeTimeout bounds the wait for the kube components to settle
	// on the target versions after UpgradeEVE has returned.
	kubeConvergeTimeout = 30 * time.Minute

	longhornNamespace = "longhorn-system"
	kubectlTimeout    = time.Minute

	// expectedVersionsFile is where the kube container ships the
	// component versions its image expects.
	expectedVersionsFile = "/etc/expected_versions.yaml"
	// appliedKubeVersionFile records, per node, the last kube version whose
	// component upgrade pass completed. kube-init runs the pass only when
	// its build carries a higher number, and never when it carries a lower
	// one.
	appliedKubeVersionFile = "/var/lib/applied-kube-version"

	dataMountDir   = "/mnt/data"
	dataVolumeSize = 512 * evetest.MiB
	dataMarker     = "kube-upgrade-marker"
)

// kubeComponents are the components the upgrade pass covers, by their key
// in expectedVersionsFile, in the order the pass visits them.
var kubeComponents = []string{"multus", "kubevirt", "cdi", "longhorn"}

// appShell is the part of EdgeDevice and EdgeCluster used to run a command
// inside the test app, so the marker helpers serve both tests.
type appShell interface {
	RunShellScriptInsideApp(appUUID uuid.UUID, auth evetest.AuthMethod,
		script string, timeout time.Duration,
		stdoutWatchdogTimeout time.Duration) (stdout, stderr string, err error)
}

// findDataDevice is a shell snippet that sets $dev to the guest block device
// of the data volume: the one of exactly dataVolumeSize with nothing mounted
// from it. EVE-k does not mount a container app's volume at its MountDir
// (lf-edge/eve#6145), so the marker goes on the raw device.
var findDataDevice = fmt.Sprintf(`dev=
for d in /dev/vd[a-z] /dev/sd[a-z]; do
  [ -b "$d" ] || continue
  grep -q "^$d" /proc/mounts && continue
  [ $(( $(cat /sys/block/${d#/dev/}/size) * 512 )) -eq %d ] && { dev=$d; break; }
done
[ -n "$dev" ] || { echo "no unmounted %d-byte disk" >&2; grep . /sys/block/*/size >&2; exit 1; }
`, dataVolumeSize, dataVolumeSize)

// writeDataMarker writes dataMarker to the start of the app's data volume.
// Reading it back after the upgrade shows the volume kept its data through
// the component upgrades.
func writeDataMarker(t *WithT, app appShell, appUUID uuid.UUID,
	auth evetest.AuthMethod) {
	script := findDataDevice + fmt.Sprintf(
		"printf '%%s\\n' %s | dd of=\"$dev\" bs=512 count=1 conv=sync,fsync 2>/dev/null",
		dataMarker)
	t.Eventually(func(t Gomega) {
		_, stderr, err := app.RunShellScriptInsideApp(appUUID, auth, script,
			20*time.Second, 0)
		t.Expect(err).ToNot(HaveOccurred(), stderr)
	}, 3*time.Minute, 5*time.Second).Should(Succeed())
}

// expectDataMarker waits until the app answers and its data volume still
// holds dataMarker, read past the guest's page cache.
func expectDataMarker(t *WithT, app appShell, appUUID uuid.UUID,
	auth evetest.AuthMethod, timeout time.Duration) {
	script := findDataDevice +
		`dd if="$dev" bs=512 count=1 iflag=direct 2>/dev/null | head -n 1`
	t.Eventually(func(t Gomega) {
		out, stderr, err := app.RunShellScriptInsideApp(appUUID, auth, script,
			20*time.Second, 0)
		t.Expect(err).ToNot(HaveOccurred(), stderr)
		t.Expect(strings.TrimSpace(out)).To(Equal(dataMarker))
	}, timeout, 5*time.Second).Should(Succeed())
}

// kubeExec runs a command inside the device's kube container.
func kubeExec(device *evetest.EdgeDevice, cmd string) (string, error) {
	out, _, err := device.RunShellScript("eve exec kube "+cmd, kubectlTimeout, 0)
	return strings.TrimSpace(out), err
}

// appliedKubeVersion returns the number in the device's
// appliedKubeVersionFile. The device's API does not report it.
func appliedKubeVersion(device *evetest.EdgeDevice) (int, error) {
	out, err := kubeExec(device, "cat "+appliedKubeVersionFile)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(out)
}

// expectAppliedKubeVersion waits until the device has recorded an applied
// kube version, which it does once its first component pass completes, and
// returns it.
func expectAppliedKubeVersion(t *WithT, device *evetest.EdgeDevice,
	timeout time.Duration) int {
	var applied int
	t.Eventually(func(g Gomega) {
		var err error
		applied, err = appliedKubeVersion(device)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(applied).To(BeNumerically(">", 0))
	}, timeout, 10*time.Second).Should(Succeed())
	return applied
}

// expectedKubeVersions returns the component versions the device's running
// EVE image targets. Reading them from the device rather than from the
// source tree keeps the test correct for whichever build the device was
// upgraded to.
func expectedKubeVersions(device *evetest.EdgeDevice) (map[string]string, error) {
	out, err := kubeExec(device, "cat "+expectedVersionsFile)
	if err != nil {
		return nil, err
	}
	versions := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if found && !strings.HasPrefix(key, "#") {
			versions[key] = strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}
	for _, comp := range kubeComponents {
		if versions[comp] == "" {
			return nil, fmt.Errorf("no %s entry in %s", comp, expectedVersionsFile)
		}
	}
	return versions, nil
}

// kubectlJSON runs kubectl get with JSON output and decodes it into out.
func kubectlJSON(device *evetest.EdgeDevice, args string, out any) error {
	raw, err := device.RunKubectl(args+" -o json", kubectlTimeout)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(raw), out)
}

// podTemplate is the part of a Deployment or DaemonSet the version checks
// read.
type podTemplate struct {
	Spec struct {
		Template struct {
			Spec struct {
				Containers []struct {
					Image string `json:"image"`
					Env   []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"env"`
				} `json:"containers"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
}

// imageTag returns the tag of a container image reference, or "" if it
// has none.
func imageTag(image string) string {
	name := image[strings.LastIndex(image, "/")+1:]
	_, tag, _ := strings.Cut(name, ":")
	return tag
}

// installedKubeVersions returns the version each kube component runs,
// read the way the kube container's own upgrade helper reads it, except
// for Longhorn, where Longhorn's own record of the installed version is
// used.
func installedKubeVersions(device *evetest.EdgeDevice) (map[string]string, error) {
	versions := make(map[string]string)

	var multus podTemplate
	if err := kubectlJSON(device, "-n kube-system get daemonset kube-multus-ds",
		&multus); err != nil {
		return nil, err
	}
	if c := multus.Spec.Template.Spec.Containers; len(c) > 0 {
		versions["multus"] = imageTag(c[0].Image)
	}

	var kubevirt struct {
		Status struct {
			OperatorVersion string `json:"operatorVersion"`
		} `json:"status"`
	}
	if err := kubectlJSON(device, "-n kubevirt get kubevirt kubevirt",
		&kubevirt); err != nil {
		return nil, err
	}
	versions["kubevirt"] = kubevirt.Status.OperatorVersion

	var cdi podTemplate
	if err := kubectlJSON(device, "-n cdi get deployment cdi-operator",
		&cdi); err != nil {
		return nil, err
	}
	if c := cdi.Spec.Template.Spec.Containers; len(c) > 0 {
		for _, env := range c[0].Env {
			if env.Name == "OPERATOR_VERSION" {
				versions["cdi"] = env.Value
			}
		}
	}

	var longhorn struct {
		Value string `json:"value"`
	}
	if err := kubectlJSON(device, "-n "+longhornNamespace+
		" get settings.longhorn.io current-longhorn-version", &longhorn); err != nil {
		return nil, err
	}
	versions["longhorn"] = longhorn.Value

	return versions, nil
}

// longhornVolume is the part of a volumes.longhorn.io object the
// convergence check reads.
type longhornVolume struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Image string `json:"image"`
	} `json:"spec"`
	Status struct {
		CurrentImage string `json:"currentImage"`
	} `json:"status"`
}

// expectKubeComponentsConverged waits until the cluster the device belongs
// to runs the component versions the device's EVE image targets: every
// component the upgrade pass covers is at its target version, every
// Longhorn volume runs the target engine image, and the device reports no
// failed or unfinished kube component update. It also requires that the
// device's applied kube version did not go below appliedBefore, and returns
// the value found.
//
// Whether an upgrade pass ran depends on the two builds: it runs only when
// the target carries a higher kube version than the node has applied. A
// target that changes a component version without raising its kube version
// leaves the component behind, and this check fails.
func expectKubeComponentsConverged(t *WithT, device *evetest.EdgeDevice,
	appliedBefore int, timeout time.Duration) int {
	log := evetest.Logger()
	var applied int
	t.Eventually(func(g Gomega) {
		// kube-init does not retry a failed component update, so there is
		// nothing left to wait for.
		info := device.GetClusterUpdateInfo()
		switch info.GetStatus() {
		case eveinfo.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_FAILED,
			eveinfo.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_DOWNLOAD_FAILED:
			StopTrying(fmt.Sprintf("kube component %s update failed: %s",
				info.GetComponent(), info.GetError().GetDescription())).Now()
		}

		target, err := expectedKubeVersions(device)
		g.Expect(err).ToNot(HaveOccurred())
		installed, err := installedKubeVersions(device)
		g.Expect(err).ToNot(HaveOccurred())
		for _, comp := range kubeComponents {
			g.Expect(installed[comp]).To(Equal(target[comp]),
				"%s runs %s, EVE targets %s", comp, installed[comp], target[comp])
		}

		var volumes struct {
			Items []longhornVolume `json:"items"`
		}
		g.Expect(kubectlJSON(device, "-n "+longhornNamespace+
			" get volumes.longhorn.io", &volumes)).To(Succeed())
		g.Expect(volumes.Items).ToNot(BeEmpty())
		for _, vol := range volumes.Items {
			g.Expect(vol.Spec.Image).To(HaveSuffix(":"+target["longhorn"]),
				"volume %s engine image", vol.Metadata.Name)
			g.Expect(vol.Status.CurrentImage).To(Equal(vol.Spec.Image),
				"volume %s running engine image", vol.Metadata.Name)
		}

		// A nil report means no component needed an update.
		g.Expect(info.GetStatus()).To(BeElementOf(
			eveinfo.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_UNSPECIFIED,
			eveinfo.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_COMPLETED),
			"kube component %s update still in progress", info.GetComponent())

		applied, err = appliedKubeVersion(device)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(applied).To(BeNumerically(">=", appliedBefore),
			"applied kube version went down")
		log.Infof("Kube components converged on %v across %d Longhorn volumes, "+
			"applied kube version %d -> %d",
			target, len(volumes.Items), appliedBefore, applied)
	}, timeout, 30*time.Second).Should(Succeed())
	return applied
}
