// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package quorum

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/lf-edge/eve/pkg/kube/kube-init/clustermode"
	"github.com/lf-edge/eve/pkg/kube/kube-init/edgenodeinfo"
	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// resetConfigDir holds the config k3s --cluster-reset runs against.
//
// Out of band, never the drop-ins in /etc/rancher/k3s. k3s refuses to
// reset while a join URL is set, and the drop-in that carries it is
// rewritten from cluster status on every pass through CONFIGURING, so
// editing it would be undone by the next config change or EVE upgrade.
// k3s takes its drop-in directory from --config, so a directory of our
// own with no .d beside it is read exactly as written.
var resetConfigDir = "/run/kube/cluster-reset"

// Promote forces this node's etcd into a single-member cluster and
// leaves it the sole bootstrap, which is how a cluster that has lost
// quorum starts agreeing with itself again.
//
// The caller routes to CONFIGURING afterwards rather than straight to
// STARTING_K3S: the drop-ins still describe the cluster as it was, and
// re-rendering them against current status is what makes this node the
// seed. No config surgery is needed here: writeBootstrapConfig already
// emits the rejoin-own-cluster form once etcd is initialised.
func Promote(ctx context.Context, sup *k3s.Supervisor, cs *k3s.ClusterStatus) error {
	// Held across the whole reset: a witness that joins mid-reset lands
	// in the membership the reset is about to discard.
	if err := HoldWitnessFence("cluster reset in progress"); err != nil {
		return err
	}
	if err := sup.Stop(); err != nil {
		return fmt.Errorf("stop k3s before reset: %w", err)
	}
	if _, err := SnapshotDB(); err != nil {
		// A recovery that cannot leave a copy behind is still better
		// than a cluster that stays down, so this is not fatal. The
		// operator loses the ability to undo it by hand.
		log.Printf("WARNING: no datastore snapshot before reset: %v", err)
	}
	if err := writeResetConfig(cs); err != nil {
		return err
	}
	if err := runClusterReset(ctx, cs); err != nil {
		return err
	}
	// The reset preserves every Kubernetes object, so the dead seed's
	// masterlease entry survives it. Left there, k3s's endpoint
	// reconciler keeps advertising an address nothing answers.
	if err := state.Mark(clustermode.MasterleaseCleanupFlag); err != nil {
		log.Printf("WARNING: arm masterlease cleanup: %v", err)
	}
	return nil
}

// writeResetConfig renders the standalone config the reset runs with:
// enough to identify this node, and deliberately no server URL.
func writeResetConfig(cs *k3s.ClusterStatus) error {
	if err := os.MkdirAll(resetConfigDir, 0755); err != nil {
		return fmt.Errorf("create %s: %w", resetConfigDir, err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "token: %q\n", cs.EncryptedToken)
	fmt.Fprintf(&b, "node-ip: %q\n", cs.ClusterIP)
	// Carried explicitly: the reset reads this file and no drop-in
	// directory, so without it k3s falls back to the hostname, which on
	// EVE is the device UUID, and rewrites the etcd member under a name
	// that no longer matches the node's. Normalised as WriteNodeName
	// does, so the reset names the node exactly as k3s otherwise would.
	// Not fatal if unavailable: a recovery that refuses to run is worse
	// than a misnamed member.
	if deviceName := edgenodeinfo.DeviceName(); deviceName == "" {
		log.Printf("WARNING: reset config has no node-name: device name unavailable")
	} else {
		fmt.Fprintf(&b, "node-name: %q\n", state.ToK8sName(deviceName))
	}
	path := filepath.Join(resetConfigDir, "config.yaml")
	if err := state.AtomicWriteFile(path, []byte(b.String()), 0600); err != nil {
		return fmt.Errorf("write reset config: %w", err)
	}
	return nil
}

// runClusterReset execs k3s once, to completion. Not through the
// supervisor: this is a one-shot that must exit before k3s can be
// started again, not a service to keep alive.
func runClusterReset(ctx context.Context, cs *k3s.ClusterStatus) error {
	args := []string{
		"server",
		"--cluster-reset",
		"--config", filepath.Join(resetConfigDir, "config.yaml"),
		// Explicit, because k3s has been seen to pick the device's LAN
		// address for the rewritten member entry rather than the
		// cluster one, leaving a member nobody can reach.
		"--node-ip=" + cs.ClusterIP,
	}
	log.Printf("running k3s %s", strings.Join(args, " "))
	out, err := exec.CommandContext(ctx, k3s.K3sSymlink, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("cluster reset: %w (%s)", err, tail(string(out)))
	}
	log.Printf("cluster reset complete: %s", tail(string(out)))
	return nil
}

// tail returns the last few lines of command output, which is where
// k3s puts the reason it failed.
func tail(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > 8 {
		lines = lines[len(lines)-8:]
	}
	return strings.Join(lines, "\n")
}
