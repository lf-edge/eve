// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/edgenodeinfo"
	"github.com/lf-edge/eve/pkg/kube/kube-init/encconfig"
	"github.com/lf-edge/eve/pkg/kube/kube-init/encstatus"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// Drop-in config files written to K3sConfigDir. k3s reads every
// *.yaml in that directory in lexical order at startup; the numeric
// prefixes choose the merge order. Slot 02 is intentionally reserved
// for future use.
const (
	NodeNameConfig   = "00-nodename.yaml"
	ClusterConfig    = "01-clusterconfig.yaml"
	DisableLocalPath = "03-enc-disable-local-path.yaml"

	// MultiNodeWatchCache disables the kube-apiserver in-memory
	// watch cache so every LIST/WATCH is served from etcd. Staged
	// on multi-node clusters only; rationale is in the YAML body.
	MultiNodeWatchCache = "04-multinode-watch-cache.yaml"

	// UserOverrideConfig wins lexical-order conflicts with the
	// kube-init-rendered drop-ins above (prefix 99).
	UserOverrideConfig = "99-k3s-config-user-overrides.yaml"
)

// multiNodeWatchCacheSrc is where the container image lands the
// YAML the Dockerfile copies from pkg/kube/cfg-manifests/. Kept
// package-local since only provisionMultiNodeWatchCache reads it.
const multiNodeWatchCacheSrc = "/etc/kube/" + MultiNodeWatchCache

const (
	// disableLocalPathContent is the YAML body for the DisableLocalPath
	// drop-in. Body kept byte-stable; k3s drop-in hashing triggers a
	// restart on any byte change. "disable+" appends to the base
	// config.yaml's list; a bare "disable" would replace it and re-enable
	// servicelb and traefik (TestEffectiveDisableKeepsServicelbAndTraefik).
	disableLocalPathContent = "# Use longhorn storage\ndisable+: local-storage\n"

	// clusterStatusPort is the HTTPS port where a bootstrap node
	// advertises its cluster UUID over the cluster interface during
	// the join-wait handshake (see statusauth.go).
	clusterStatusPort = "12346"

	// joinPollInterval is the cadence at which we re-probe the
	// bootstrap server: short enough that a normal join completes in
	// a couple of intervals, long enough that pre-bootstrap probes
	// do not flood the log.
	joinPollInterval = 10 * time.Second

	// joinAPIPort is the k3s API server port on the bootstrap node.
	joinAPIPort = "6443"

	// joinHTTPClientTimeout bounds a single probe of the bootstrap
	// server. Kept short so transient network ripples don't stretch
	// the poll interval.
	joinHTTPClientTimeout = 2 * time.Second
)

// ErrClusterStatusWithdrawn is returned by waitForBootstrapServer if
// the EdgeNodeClusterStatus payload disappears mid-wait — typically
// because zedkube withdrew the cluster config.
var ErrClusterStatusWithdrawn = errors.New("EdgeNodeClusterStatus withdrawn during wait")

// ErrBootstrapUnreachable wraps an attempt-count threshold for
// non-transient probe failures (DNS NXDOMAIN, TLS verification).
// waitForBootstrapServer surfaces this so the FSM that lands later
// can route between "controller misconfigured" (fatal) and "still
// coming up" (transient).
var ErrBootstrapUnreachable = errors.New("bootstrap server unreachable after non-transient errors")

// ClusterStatus is the kube-init-local view of zedkube's
// EdgeNodeClusterStatus payload. Only the fields kube-init consumes
// are mirrored; pkg/pillar is deliberately NOT imported so kube-init
// builds in isolation.
type ClusterStatus struct {
	ClusterInterface string
	IsBootstrapNode  bool
	JoinServerIP     string
	EncryptedToken   string
	ClusterIP        string
	// PrefixLen is the cluster network prefix length derived from
	// the pillar EdgeNodeClusterStatus.ClusterIPPrefix.Mask field
	// (0 if not present). Used by callers that need to compute
	// the cluster subnet (e.g. clustermode.CleanupStaleMasterleases).
	PrefixLen        int
	ClusterIPIsReady bool
	ClusterID        string
	// WitnessIP is the address the witness binds its etcd to, empty
	// when the controller configured no witness. Set on every node,
	// since NIM needs it too, but only acted on by the node that owns
	// JoinServerIP.
	WitnessIP string
	// QuorumRecoveryGeneration is the controller's quorum-loss recovery
	// counter. A change means the cluster was forcibly reset, so local
	// etcd state belongs to a cluster that no longer exists.
	QuorumRecoveryGeneration uint32
}

// ClusterType represents the EVE-API cluster-storage type. The
// numeric values match the controller-side enum so the int field
// in EdgeNodeClusterConfig can be cast directly.
type ClusterType int

// Known ClusterType values. Anything else is treated as
// Unspecified by IsValid.
const (
	// ClusterTypeUnspecified is the default when the controller
	// has not declared a cluster type; single-node behaviour
	// applies.
	ClusterTypeUnspecified ClusterType = 0
	// ClusterTypeBase is the K3S_BASE topology — externally
	// managed storage, no Longhorn.
	ClusterTypeBase ClusterType = 1
	// ClusterTypeReplicated is the K3S_REPLICATED topology —
	// 3-node Longhorn with replicated storage.
	ClusterTypeReplicated ClusterType = 2
)

// IsValid returns true for the known ClusterType values.
// Unknown integers from the JSON payload are caught here rather than
// flowing through provisioning where they would silently no-op.
func (c ClusterType) IsValid() bool {
	switch c {
	case ClusterTypeUnspecified, ClusterTypeBase, ClusterTypeReplicated:
		return true
	}
	return false
}

// Configure renders every k3s drop-in needed for this device.
// Idempotent: safe to re-run.
func Configure(ctx context.Context) error {
	deviceName := edgenodeinfo.DeviceName()
	if deviceName == "" {
		return fmt.Errorf("EdgeNodeInfo subscription has not delivered yet (DeviceName empty)")
	}

	initialized, err := state.IsMarked(state.AllComponentsInitialized)
	if err != nil {
		return fmt.Errorf("check init marker: %w", err)
	}
	isFirstBoot := !initialized

	if err := os.MkdirAll(K3sConfigDir, 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	if err := WriteNodeName(deviceName); err != nil {
		return fmt.Errorf("write node name: %w", err)
	}

	changed, err := ApplyUserOverrides()
	if err != nil {
		return fmt.Errorf("apply user overrides: %w", err)
	}
	if changed {
		log.Printf("user override config updated")
	}

	cluster, err := IsClusterMode()
	if err != nil {
		return fmt.Errorf("detect cluster mode: %w", err)
	}
	if cluster {
		if err := ProvisionClusterConfig(ctx, isFirstBoot); err != nil {
			return fmt.Errorf("provision cluster config: %w", err)
		}
	} else if err := ProvisionSingleNodeConfig(deviceName); err != nil {
		return fmt.Errorf("provision single node config: %w", err)
	}
	return nil
}

// WriteNodeName writes the k3s node-name drop-in. The name is
// normalised so the on-disk node name follows the RFC 1123 DNS-label
// shape k8s requires.
func WriteNodeName(deviceName string) error {
	content := fmt.Sprintf("node-name: %s\n", state.ToK8sName(deviceName))
	return state.AtomicWriteFile(
		filepath.Join(K3sConfigDir, NodeNameConfig),
		[]byte(content), 0644)
}

// ApplyUserOverrides syncs the user-override drop-in with the source
// payload. Returns changed=true on create/update/removal so the
// caller can trigger a k3s restart only when the dir actually
// differs.
func ApplyUserOverrides() (changed bool, err error) {
	dst := filepath.Join(K3sConfigDir, UserOverrideConfig)

	srcData, srcErr := os.ReadFile(UserOverrideSrc)
	switch {
	case srcErr == nil:
	case errors.Is(srcErr, os.ErrNotExist):
		// No source: drop any stale dst.
		rmErr := os.Remove(dst)
		switch {
		case rmErr == nil:
			log.Printf("removed stale user override config")
			return true, nil
		case errors.Is(rmErr, os.ErrNotExist):
			return false, nil
		default:
			return false, fmt.Errorf("remove stale override %s: %w", dst, rmErr)
		}
	default:
		return false, fmt.Errorf("read %s: %w", UserOverrideSrc, srcErr)
	}

	// Source exists. Short-circuit when dst already matches.
	if dstData, dstErr := os.ReadFile(dst); dstErr == nil {
		if string(srcData) == string(dstData) {
			return false, nil
		}
	} else if !errors.Is(dstErr, os.ErrNotExist) {
		return false, fmt.Errorf("read %s: %w", dst, dstErr)
	}

	if err := state.AtomicWriteFile(dst, srcData, 0644); err != nil {
		return false, fmt.Errorf("write override %s: %w", dst, err)
	}
	return true, nil
}

// GetClusterStatus returns the cached EdgeNodeClusterStatus,
// translated and validated into kube-init's local ClusterStatus
// shape. The returned ClusterStatus has every essential string
// field non-empty; missing or empty fields surface as an error.
// "No delivery yet" returns ErrClusterStatusUnavailable so the
// caller can distinguish that from a malformed payload.
func GetClusterStatus() (*ClusterStatus, error) {
	raw, ok := encstatus.Get()
	if !ok {
		return nil, ErrClusterStatusUnavailable
	}
	cs := &ClusterStatus{
		ClusterInterface: raw.ClusterInterface,
		IsBootstrapNode:  raw.BootstrapNode,
		EncryptedToken:   raw.EncryptedClusterToken,
		ClusterIPIsReady: raw.ClusterIPIsReady,
	}
	if raw.JoinServerIP != nil {
		cs.JoinServerIP = raw.JoinServerIP.String()
	}
	if raw.ClusterIPPrefix != nil {
		if raw.ClusterIPPrefix.IP != nil {
			cs.ClusterIP = raw.ClusterIPPrefix.IP.String()
		}
		if len(raw.ClusterIPPrefix.Mask) > 0 {
			// net.IPMask.Size returns (ones, bits); 0/0 means
			// the mask is not canonical and we should ignore
			// it rather than treat it as /0.
			ones, _ := raw.ClusterIPPrefix.Mask.Size()
			cs.PrefixLen = ones
		}
	}
	if raw.ClusterID.UUID != uuid.Nil {
		cs.ClusterID = raw.ClusterID.UUID.String()
	}
	if raw.WitnessIP != nil {
		cs.WitnessIP = raw.WitnessIP.String()
	}
	cs.QuorumRecoveryGeneration = raw.QuorumRecoveryGeneration
	if err := cs.validate(); err != nil {
		return nil, fmt.Errorf("validate EdgeNodeClusterStatus: %w", err)
	}
	return cs, nil
}

// ErrClusterStatusUnavailable is returned by GetClusterStatus
// when the EdgeNodeClusterStatus subscription has not delivered
// yet OR was deleted. Callers that want to distinguish a
// not-yet-arrived state from a malformed payload check
// errors.Is(err, ErrClusterStatusUnavailable).
var ErrClusterStatusUnavailable = errors.New("EdgeNodeClusterStatus unavailable")

// validate has a pointer receiver only to match the rest of this
// file's *ClusterStatus shapes; it does not mutate the receiver.
func (cs *ClusterStatus) validate() error {
	switch {
	case cs.ClusterInterface == "":
		return errors.New("ClusterInterface is empty")
	case cs.JoinServerIP == "":
		return errors.New("JoinServerIP is empty")
	case cs.EncryptedToken == "":
		return errors.New("EncryptedClusterToken is empty")
	case cs.ClusterIP == "":
		return errors.New("ClusterIPPrefix.IP is empty")
	case !cs.ClusterIPIsReady:
		return errors.New("ClusterIPIsReady is false")
	case cs.ClusterID == "":
		return errors.New("ClusterID.UUID is empty")
	}
	return nil
}

// GetClusterType reads ClusterType from the cached
// EdgeNodeClusterConfig subscription. On no delivery yet (or
// after a Delete), ClusterTypeReplicated is returned.
//
// The second return value is always nil today; the signature is
// kept so future versions can surface a real error without a
// signature change.
func GetClusterType() (ClusterType, error) {
	ct := encconfig.ClusterType()
	if ct == types.ClusterTypeNone {
		return ClusterTypeReplicated, nil
	}
	return ClusterType(ct), nil
}

// IsClusterMode reports whether the device is currently configured
// as part of an HA cluster.
func IsClusterMode() (bool, error) {
	return state.IsMarked(state.EdgeNodeClusterMode)
}

// ClusterStatusPresent reports whether the EdgeNodeClusterStatus
// subscription holds a payload representing a live cluster.
// Returns false on no delivery yet OR when the payload carries
// the zero ClusterID UUID (which is how a controller-side
// cluster delete surfaces on this non-Persistent topic).
//
// The error return is always nil today; kept for signature
// stability.
func ClusterStatusPresent() (bool, error) {
	return encstatus.Present(), nil
}

// ProvisionClusterConfig writes the cluster-mode drop-ins for the
// current node role: cluster-init for the bootstrap node, server-join
// for everyone else. On first boot for a joining node the call blocks
// until the bootstrap server is reachable and reports a matching
// cluster UUID.
//
// It also resets this node's local k3s server state (certs, tokens,
// managed-etcd datastore) when it no longer matches the identity the
// controller assigns now — otherwise k3s can silently keep a foreign
// CA, and the failure surfaces much later as a permanent "certificate
// signed by unknown authority". No recorded identity yet just records
// the current one, without a reset. See resetStaleServerState for the
// QuorumRecoveryGeneration/bootstrap-node nuance.
func ProvisionClusterConfig(ctx context.Context, isFirstBoot bool) error {
	cs, err := GetClusterStatus()
	if err != nil {
		return fmt.Errorf("get cluster status: %w", err)
	}
	current := Generation{ClusterID: cs.ClusterID, Counter: cs.QuorumRecoveryGeneration}

	reset, err := resetStaleServerState(current, cs.IsBootstrapNode)
	if err != nil {
		return err
	}
	if reset {
		// Local state is gone, so this is a genuine first join
		// regardless of this device's own boot/init history.
		isFirstBoot = true
	}

	if err := provisionDisableLocalPath(); err != nil {
		return fmt.Errorf("provision disable-local-path: %w", err)
	}
	if err := provisionMultiNodeWatchCache(); err != nil {
		return fmt.Errorf("provision multi-node watch cache: %w", err)
	}
	clusterCfgPath := filepath.Join(K3sConfigDir, ClusterConfig)
	if cs.IsBootstrapNode {
		err = writeBootstrapConfig(clusterCfgPath, cs, isFirstBoot)
	} else {
		err = writeJoinConfig(ctx, clusterCfgPath, cs, isFirstBoot)
	}
	if err != nil {
		return err
	}
	return writeClusterIdentity(current)
}

// clusterIdentityPath records the Generation the node's local k3s
// server state (k3sServerDir) belongs to. Lives alongside that state,
// not under /var/lib/*_initialized (ephemeral — see
// AllComponentsInitialized), since its lifetime must track the k3s
// state, not the current boot.
var clusterIdentityPath = "/var/lib/rancher/k3s/cluster-identity"

// k3sServerDir is k3s's own persistent state: TLS material, the
// managed-etcd datastore, and k3s's bootstrap-data cache. Removed by
// DiscardClusterState on a cluster-identity mismatch.
var k3sServerDir = "/var/lib/rancher/k3s/server"

// SingleNodeClusterID is the ClusterID recorded for local k3s server
// state that belongs to no cluster: the node's own pre-cluster CA,
// tokens and datastore, as put back by a cluster to single-node restore.
const SingleNodeClusterID = "single-node"

// RecordSingleNodeIdentity marks the local k3s server state as the node's
// own single-node state. Call it after restoring /var/lib from the
// pre-cluster snapshot: the restore leaves the cluster identity written on
// join next to the restored single-node CA, so the next join would keep
// that CA and fail with "certificate signed by unknown authority".
// See resetStaleServerState.
func RecordSingleNodeIdentity() error {
	return writeClusterIdentity(Generation{ClusterID: SingleNodeClusterID})
}

// readClusterIdentity returns the Generation recorded for the node's
// local k3s server state, and whether one was recorded at all.
//
// A file that fails to parse — the single-field format a build
// predating generation tracking wrote, or a corrupt file — counts as
// no record too, so an upgrade just records the current identity
// instead of forcing a reset.
func readClusterIdentity() (identity Generation, recorded bool, err error) {
	raw, err := os.ReadFile(clusterIdentityPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Generation{}, false, nil
		}
		return Generation{}, false, fmt.Errorf("read %s: %w", clusterIdentityPath, err)
	}
	identity, recorded, err = ParseGeneration(string(raw))
	if err != nil {
		return Generation{}, false, nil
	}
	return identity, recorded, nil
}

// writeClusterIdentity records identity as what the node's local k3s
// server state now belongs to.
func writeClusterIdentity(identity Generation) error {
	if err := state.AtomicWriteFile(clusterIdentityPath, []byte(identity.String()+"\n"), 0644); err != nil {
		return fmt.Errorf("write %s: %w", clusterIdentityPath, err)
	}
	return nil
}

// Markers DiscardClusterState clears and the kubeconfigs it removes with
// the PKI they describe. Vars so tests can redirect them.
var (
	nodeLabelsMarker   = state.NodeLabelsInitialized
	debugUserMarker    = state.DebugUserInitialized
	derivedKubeconfigs = []string{state.K3sKubeconfig, KubeconfigCopy}
)

// DiscardClusterState drops what the node still holds from the cluster it
// is leaving, so the next cluster-init or join starts clean instead of
// reconciling against, and keeping, material from a different cluster.
// Called with k3s stopped, from the single to cluster transition and from
// resetStaleServerState, which are the two ways a node ends up joining
// with local state that is not the cluster's.
//
// wipeServerDir removes all of k3s's server state (datastore, tokens, PKI),
// for a node whose state belongs to a different cluster. Without it only
// the PKI goes, for a node that keeps its datastore across the transition.
//
// What goes, and why it is tied to a join:
//
//   - The PKI, unless the node is bootstrap and keeps its state: a joiner
//     is re-issued the cluster's CA, so a surviving cert signed by the old
//     one keeps being used. The debug-user marker goes with it, as its
//     certificate is signed by the client CA that is removed.
//   - The pod-subnet CNI state of a joiner, which would otherwise network a
//     pod against the retired subnet. A bootstrap node keeps its subnet.
//   - The node-labels marker, always. The node comes back as a new Node
//     object without the labels and the Longhorn default-disk annotation
//     kube-init stamped on the old one. With the marker left set the health
//     tick never re-stamps them, Longhorn creates the node with no disk,
//     and volumemgr waits on cluster storage forever, leaving every app on
//     it in Init.
//
// Only a failure to remove the server state or PKI is returned: leaving
// that behind guarantees the join fails at the TLS handshake. The CNI
// state and markers are best-effort, as a stale one delays or degrades the
// join without breaking it.
func DiscardClusterState(isBootstrap, wipeServerDir bool) error {
	var joined error
	dropPKI := wipeServerDir || !isBootstrap

	if wipeServerDir {
		if err := os.RemoveAll(k3sServerDir); err != nil {
			joined = errors.Join(joined, fmt.Errorf("remove %s: %w", k3sServerDir, err))
		}
	}
	if dropPKI {
		if err := removeServerTLSDir(
			filepath.Join(k3sServerDir, "tls"),
			filepath.Join(k3sServerDir, "cred", "ipsec.psk"),
			derivedKubeconfigs...); err != nil {
			joined = errors.Join(joined, err)
		}
		if err := state.Unmark(debugUserMarker); err != nil {
			log.Printf("warning: %v", err)
		}
	}
	if !isBootstrap {
		if err := removeStaleCNIState(flannelSubnetEnv, cniIPAMStateDir); err != nil {
			log.Printf("warning: clear stale CNI state: %v", err)
		}
	}
	if err := state.Unmark(nodeLabelsMarker); err != nil {
		log.Printf("warning: %v", err)
	}
	return joined
}

// resetStaleServerState resets local k3s server state when it no
// longer matches current, and reports whether it did so the caller
// can force a genuine first join regardless of boot history. No
// recorded identity at all is left alone — see readClusterIdentity.
//
// isBootstrapNode exempts a QuorumRecoveryGeneration-only mismatch for
// the node the controller currently names bootstrap: that bump is the
// recovery this node is about to perform (package quorum), which
// needs the existing etcd data to reset from — wiping it first
// destroys exactly what it needs. A ClusterID change always resets
// regardless of role; that's a different cluster, not a recovery.
//
// A restored single-node tree (SingleNodeClusterID) is reset for
// every joining node, since its CA is not the cluster's, and kept by
// the bootstrap node, which seeds the cluster from it.
func resetStaleServerState(current Generation, isBootstrapNode bool) (reset bool, err error) {
	recordedIdentity, recorded, err := readClusterIdentity()
	if err != nil {
		return false, fmt.Errorf("read cluster identity: %w", err)
	}
	if !recorded {
		log.Printf("no cluster identity recorded yet for local k3s server state; recording %s", current)
		return false, nil
	}
	if recordedIdentity.ClusterID == SingleNodeClusterID && isBootstrapNode {
		log.Printf("local k3s server state is this node's own single-node state; "+
			"bootstrap node keeps it as the seed for cluster %s", current)
		return false, nil
	}
	if recordedIdentity == current {
		log.Printf("local k3s server state identity matches %s, no reset needed", current)
		return false, nil
	}
	if recordedIdentity.ClusterID == current.ClusterID && isBootstrapNode {
		log.Printf("local k3s server state generation %d is behind cluster %q's %d, "+
			"but this node is bootstrap — leaving it for quorum recovery to handle",
			recordedIdentity.Counter, current.ClusterID, current.Counter)
		return false, nil
	}
	log.Printf("local k3s server state belongs to %s, controller assigns %s — resetting before provisioning",
		recordedIdentity, current)
	if err := DiscardClusterState(isBootstrapNode, true); err != nil {
		return false, fmt.Errorf("reset k3s server state for cluster change: %w", err)
	}
	return true, nil
}

// ProvisionSingleNodeConfig cleans up cluster-mode drop-ins left
// over from a previous cluster membership.
func ProvisionSingleNodeConfig(deviceName string) error {
	clusterCfgPath := filepath.Join(K3sConfigDir, ClusterConfig)
	if err := removeIfExists(clusterCfgPath); err != nil {
		return fmt.Errorf("remove stale cluster config: %w", err)
	}
	dlpPath := filepath.Join(K3sConfigDir, DisableLocalPath)
	if err := removeIfExists(dlpPath); err != nil {
		log.Printf("warning: remove %s: %v", dlpPath, err)
	}
	wcPath := filepath.Join(K3sConfigDir, MultiNodeWatchCache)
	if err := removeIfExists(wcPath); err != nil {
		log.Printf("warning: remove %s: %v", wcPath, err)
	}
	log.Printf("single-node config for %s: node-name only",
		state.ToK8sName(deviceName))
	return nil
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func writeBootstrapConfig(path string, cs *ClusterStatus, isFirstBoot bool) error {
	var buf strings.Builder
	// A bootstrap node has to initialize the etcd cluster unless it has
	// already done so. isFirstBoot alone is the wrong predicate: on a
	// single→cluster transition the device is long past first boot, yet
	// its managed-etcd datastore has never been initialized (it ran
	// single-node against kine). Emitting the rejoin stanza there points
	// the node at its own apiserver, which cannot come up until bootstrap
	// data exists — k3s then dies on every restart with "Managed etcd
	// cluster not yet initialized" plus a connection refused to itself,
	// and the node never recovers.
	if isFirstBoot || !etcdClusterInitialized() {
		buf.WriteString("cluster-init: true\n")
	} else {
		// Restart: rejoin our own cluster rather than re-bootstrap.
		fmt.Fprintf(&buf, "server: \"https://%s:%s\"\n",
			bracketIPv6(cs.JoinServerIP), joinAPIPort)
	}
	fmt.Fprintf(&buf, "token: \"%s\"\n", cs.EncryptedToken)
	buf.WriteString("tls-san:\n")
	fmt.Fprintf(&buf, "  - \"%s\"\n", cs.JoinServerIP)
	fmt.Fprintf(&buf, "flannel-iface: \"%s\"\n", cs.ClusterInterface)
	fmt.Fprintf(&buf, "node-ip: \"%s\"\n", cs.ClusterIP)
	if err := state.AtomicWriteFile(path, []byte(buf.String()), 0644); err != nil {
		return fmt.Errorf("write bootstrap config: %w", err)
	}
	log.Printf("bootstrap config written (firstBoot=%v, etcdInitialized=%v)",
		isFirstBoot, etcdClusterInitialized())
	return nil
}

// etcdMemberDir is k3s' managed-etcd member directory. Declared as a var
// so tests can shadow it.
var etcdMemberDir = "/var/lib/rancher/k3s/server/db/etcd/member"

// etcdClusterInitialized reports whether this node already holds an
// initialized managed-etcd datastore.
//
// member/ is the only trustworthy signal. k3s creates the parent
// .../db/etcd/ directory (and a "name" file in it) on any server start,
// including a single-node/kine one that never runs etcd at all — so
// neither the directory nor that file distinguishes "etcd bootstrapped"
// from "etcd was never initialized". etcd itself creates member/ only
// once it has written its datastore.
func etcdClusterInitialized() bool {
	fi, err := os.Stat(etcdMemberDir)
	return err == nil && fi.IsDir()
}

func writeJoinConfig(ctx context.Context, path string, cs *ClusterStatus, isFirstBoot bool) error {
	var buf strings.Builder
	fmt.Fprintf(&buf, "server: \"https://%s:%s\"\n",
		bracketIPv6(cs.JoinServerIP), joinAPIPort)
	fmt.Fprintf(&buf, "token: \"%s\"\n", cs.EncryptedToken)
	fmt.Fprintf(&buf, "flannel-iface: \"%s\"\n", cs.ClusterInterface)
	fmt.Fprintf(&buf, "node-ip: \"%s\"\n", cs.ClusterIP)
	if err := state.AtomicWriteFile(path, []byte(buf.String()), 0644); err != nil {
		return fmt.Errorf("write join config: %w", err)
	}
	log.Printf("join config written for server %s", cs.JoinServerIP)
	if isFirstBoot {
		apiURL := fmt.Sprintf("https://%s:%s",
			bracketIPv6(cs.JoinServerIP), joinAPIPort)
		statusURL := fmt.Sprintf("https://%s:%s/status",
			bracketIPv6(cs.JoinServerIP), clusterStatusPort)
		if err := waitForBootstrapServer(ctx, apiURL, statusURL, cs.ClusterID,
			cs.EncryptedToken); err != nil {
			return fmt.Errorf("wait for bootstrap server: %w", err)
		}
	} else {
		log.Printf("restart case: not waiting for bootstrap server")
	}
	return nil
}

// nonTransientThreshold is the number of consecutive non-transient
// probe failures (DNS NXDOMAIN, TLS verification) tolerated before
// waitForBootstrapServer surfaces ErrBootstrapUnreachable. Picked so
// that a single misclassification doesn't fail the wait but a
// permanently misconfigured controller is reported promptly.
const nonTransientThreshold = 6

// waitForBootstrapServer polls the bootstrap node until both its k3s
// API and its cluster-status endpoint are reachable AND the
// cluster-status endpoint reports a UUID matching expectedClusterID.
// The cluster-status endpoint is reached with credentials derived
// from joinToken (statusauth.go), which authenticates the bootstrap
// node; the UUID check guards against accidentally joining a re-IP'd
// different cluster.
//
// The first probe runs immediately (do not wait one full poll
// interval before checking — the bootstrap node may already be up).
//
// The function distinguishes transient errors (connection refused,
// server still spinning up) from non-transient ones (DNS NXDOMAIN,
// TLS verification failure, HTTP 4xx/5xx). After
// nonTransientThreshold consecutive non-transient failures it
// returns ErrBootstrapUnreachable rather than spinning silently.
func waitForBootstrapServer(ctx context.Context, apiURL, statusURL, expectedClusterID,
	joinToken string) error {
	log.Printf("waiting for bootstrap server %s ...", apiURL)

	statusAuth, err := deriveClusterStatusAuth(joinToken)
	if err != nil {
		return fmt.Errorf("derive cluster-status credentials: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(clusterWaitFile), 0755); err != nil {
		log.Printf("warning: mkdir for %s: %v", clusterWaitFile, err)
	}
	if err := os.WriteFile(clusterWaitFile, []byte("1"), 0644); err != nil {
		log.Printf("warning: write %s: %v", clusterWaitFile, err)
	}
	defer func() {
		if err := os.Remove(clusterWaitFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("warning: remove %s: %v", clusterWaitFile, err)
		}
	}()

	// Disabled TLS verification is intentional and scoped to this
	// single bootstrap-discovery probe.
	//
	// The bootstrap node presents a self-signed cert generated by
	// k3s on first start. We have not joined the cluster yet, so
	// the real cluster CA is not in our trust store and cannot be
	// — that CA is what the join is going to fetch. We have to
	// dial the bootstrap node before we can trust its certificate
	// chain.
	//
	// The real authentication boundary is the cluster-status
	// endpoint a few lines below. It is reached over TLS pinned to a
	// certificate derived from the cluster join token (delivered
	// over a controller-authenticated channel), so only a node that
	// knows the token can answer, and its answer must carry
	// expectedClusterID.
	//
	// Once the join completes, k3s installs the real cluster CA
	// under /var/lib/rancher/k3s/server/tls and every other client
	// in kube-init talks verified TLS via that bundle.
	//
	// The CodeQL go/disabled-certificate-check rule flags this site
	// regardless. The lgtm[] annotation suppresses CodeQL inline;
	// the nolint:gosec annotation suppresses gosec for the same
	// reason. The PR review process is the place to confirm the
	// suppression is acceptable — see the comment trail on
	// https://github.com/lf-edge/eve/pull/5971.
	httpsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // lgtm[go/disabled-certificate-check]
		},
		Timeout: joinHTTPClientTimeout,
	}
	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: statusAuth.tlsConfig()},
		Timeout:   joinHTTPClientTimeout,
	}

	consecutiveNonTransient := 0

	probe := func(attempt int) (done bool, err error) {
		// Bail loudly if the cluster status payload was withdrawn
		// while we were waiting — the controller revoked the
		// cluster config and continuing to poll is wrong. The
		// non-Persistent topic signals withdrawal by zero
		// ClusterID, which encstatus.Present folds into "not
		// present".
		if !encstatus.Present() {
			return true, ErrClusterStatusWithdrawn
		}

		// 1. API endpoint reachable?
		resp, getErr := httpsClient.Get(apiURL)
		if getErr != nil {
			cls := classifyHTTPErr(getErr)
			if cls == probeNonTransient {
				consecutiveNonTransient++
			} else {
				consecutiveNonTransient = 0
			}
			logEveryNAttempts(attempt, 30, "attempt %d: k3s API at %s unreachable (%s): %v",
				attempt, apiURL, cls, getErr)
			return false, nil
		}
		_ = resp.Body.Close()

		// 2. Status endpoint reachable + reporting cluster UUID?
		statusBody, statusErr := fetchClusterStatus(httpClient, statusURL,
			statusAuth.authorization)
		if statusErr != nil {
			cls := classifyHTTPErr(statusErr)
			if cls == probeNonTransient {
				consecutiveNonTransient++
			} else {
				consecutiveNonTransient = 0
			}
			logEveryNAttempts(attempt, 30, "attempt %d: status endpoint %s unreachable (%s): %v",
				attempt, statusURL, cls, statusErr)
			return false, nil
		}
		consecutiveNonTransient = 0

		if !strings.HasPrefix(statusBody, "cluster:") {
			logEveryNAttempts(attempt, 30, "attempt %d: server not yet in cluster mode (got: %s)",
				attempt, statusBody)
			return false, nil
		}
		reportedUUID := strings.TrimPrefix(statusBody, "cluster:")
		if reportedUUID != expectedClusterID {
			logEveryNAttempts(attempt, 30, "attempt %d: cluster UUID mismatch: ours=%s reported=%s",
				attempt, expectedClusterID, reportedUUID)
			return false, nil
		}
		log.Printf("bootstrap server ready with matching UUID %s after %d attempts",
			expectedClusterID, attempt)
		return true, nil
	}

	// Probe once immediately so a fast bootstrap doesn't pay a full
	// joinPollInterval before the first attempt.
	if done, err := probe(1); err != nil {
		return err
	} else if done {
		return nil
	}
	if consecutiveNonTransient >= nonTransientThreshold {
		return fmt.Errorf("%w after %d consecutive non-transient probes",
			ErrBootstrapUnreachable, consecutiveNonTransient)
	}

	ticker := time.NewTicker(joinPollInterval)
	defer ticker.Stop()
	for attempt := 2; ; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		done, err := probe(attempt)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if consecutiveNonTransient >= nonTransientThreshold {
			return fmt.Errorf("%w after %d consecutive non-transient probes",
				ErrBootstrapUnreachable, consecutiveNonTransient)
		}
	}
}

// fetchClusterStatus issues one GET against the status endpoint,
// presenting authorization, and returns the trimmed body. Any read error is surfaced rather than
// silently producing an empty body (which would be indistinguishable
// from a server that legitimately hasn't entered cluster mode yet).
func fetchClusterStatus(c *http.Client, statusURL, authorization string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, statusURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", authorization)
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("status endpoint returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read status body: %w", err)
	}
	return strings.TrimSpace(string(body)), nil
}

// probeErrClass classifies an HTTP probe error for retry budgeting.
type probeErrClass int

const (
	// probeTransient is the normal "server still coming up" class:
	// connection refused, RST, timeout, server returning a 5xx while
	// k3s is bootstrapping. Worth retrying without budget pressure.
	probeTransient probeErrClass = iota
	// probeNonTransient indicates the controller / DNS / TLS chain
	// looks broken (DNS NXDOMAIN, x509 verification, permanent 4xx).
	// Budgeted: after a threshold we surface ErrBootstrapUnreachable
	// so operators get a signal instead of silent log spam.
	probeNonTransient
)

func (c probeErrClass) String() string {
	if c == probeNonTransient {
		return "non-transient"
	}
	return "transient"
}

// classifyHTTPErr maps an http.Client error onto a probeErrClass.
// Defaults to probeTransient on unknown shapes — we'd rather over-
// retry a misclassified error than fail a legitimate slow bootstrap.
func classifyHTTPErr(err error) probeErrClass {
	if err == nil {
		return probeTransient
	}
	// DNS resolution failures (NXDOMAIN, etc.) are non-transient:
	// the controller pointed us at a name that doesn't resolve.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return probeNonTransient
	}
	// TLS verification chain failures point at a real PKI mismatch,
	// not a still-spinning-up server.
	var certErr *x509.UnknownAuthorityError
	if errors.As(err, &certErr) {
		return probeNonTransient
	}
	var hostErr *x509.HostnameError
	if errors.As(err, &hostErr) {
		return probeNonTransient
	}
	// url.Error wrapping any of the above is also non-transient.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		// Recurse onto the unwrapped underlying error so the
		// classifier doesn't have to special-case url.Error
		// composition explicitly.
		if urlErr.Err != err {
			return classifyHTTPErr(urlErr.Err)
		}
	}
	return probeTransient
}

// logEveryNAttempts emits a log line only every Nth attempt so the
// boot log stays readable during a cluster join.
func logEveryNAttempts(attempt, every int, format string, args ...interface{}) {
	if attempt%every == 1 {
		log.Print(fmt.Sprintf(format, args...))
	}
}

// provisionMultiNodeWatchCache stages the multi-node watch-cache
// drop-in from the image-baked source into K3sConfigDir. Called
// only from the cluster-mode branch of Configure, so the mere
// presence of the drop-in is the "this is a multi-node cluster"
// signal to k3s. Redoes intent from upstream commit 27496ff23.
func provisionMultiNodeWatchCache() error {
	body, err := os.ReadFile(multiNodeWatchCacheSrc)
	if err != nil {
		return fmt.Errorf("read %s: %w", multiNodeWatchCacheSrc, err)
	}
	dst := filepath.Join(K3sConfigDir, MultiNodeWatchCache)
	return state.AtomicWriteFile(dst, body, 0644)
}

// provisionDisableLocalPath writes or removes the disable-local-path
// drop-in based on the controller-supplied ClusterType. Unknown
// values default to the replicated behaviour for backwards compat
// with controllers that ship a newer enum than we understand.
func provisionDisableLocalPath() error {
	ct, err := GetClusterType()
	if err != nil {
		return err
	}
	dlpPath := filepath.Join(K3sConfigDir, DisableLocalPath)
	switch ct {
	case ClusterTypeReplicated, ClusterTypeUnspecified:
		return state.AtomicWriteFile(dlpPath, []byte(disableLocalPathContent), 0644)
	case ClusterTypeBase:
		return removeIfExists(dlpPath)
	}
	// Unknown ClusterType — neither Base nor Replicated nor
	// Unspecified. Treat as Replicated (default policy) rather than
	// leaving the existing drop-in in an indeterminate state.
	log.Printf("unknown ClusterType %d: defaulting to replicated behaviour", ct)
	return state.AtomicWriteFile(dlpPath, []byte(disableLocalPathContent), 0644)
}

// bracketIPv6 wraps an IPv6 address in square brackets for use inside
// a URL. IPv4 addresses and non-IP strings are returned unchanged so
// callers can pass through hostnames.
func bracketIPv6(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() != nil {
		return addr
	}
	return "[" + addr + "]"
}

// removeStaleCNIState drops the pod-subnet state this node built up while it
// ran its own single-node cluster, so that nothing can hand out an address
// from the retired subnet once the node has joined.
//
// A node running standalone owns 10.42.0.0/24; joining assigns it a different
// podCIDR, and flannel rewrites subnet.env to match. Between the join and that
// rewrite the flannel CNI plugin still reads the old subnet, so a pod networked
// in that window is given an address the cluster routes to a different node.
// It never recovers: the address is fixed for the pod's lifetime, and a
// daemonset pod that crash-loops on it restarts in place and keeps it.
//
// Removing subnet.env makes that window fail closed instead. A CNI ADD with no
// subnet to read fails, kubelet retries, and the pod is networked correctly
// once flannel has published the new subnet — where an ADD that "succeeds"
// against the stale subnet is permanent.
//
// The host-local reservations go too. They are keyed by network name rather
// than by subnet, so the retired subnet's entries would otherwise sit in the
// directory indefinitely; flannel and host-local rebuild both paths on the
// next start.
func removeStaleCNIState(subnetEnv, ipamDir string) error {
	var joined error
	if err := removeIfExists(subnetEnv); err != nil {
		log.Printf("warning: remove %s: %v", subnetEnv, err)
		joined = errors.Join(joined, fmt.Errorf("remove %s: %w", subnetEnv, err))
	}
	if err := os.RemoveAll(ipamDir); err != nil {
		log.Printf("warning: remove %s: %v", ipamDir, err)
		joined = errors.Join(joined, fmt.Errorf("remove %s: %w", ipamDir, err))
	}
	return joined
}

// removeServerTLSDir empties the k3s server TLS directory so a joining
// node is re-issued its whole PKI under the bootstrap node's CA. See
// DiscardClusterState for when it runs.
//
// Everything under server/tls goes, not a named subset of CA files.
// k3s rewrites what it manages as bootstrap data from the datastore on
// the next start ("Updating bootstrap data on disk from datastore"), so
// deleting too much costs nothing — whereas anything left behind that
// was signed by the retired single-node CA keeps being used.
// dynamic-cert.json is the one that bites: it caches the whole
// kube-system/k3s-serving Secret and is preloaded before the datastore
// is up, so a surviving copy makes the local supervisor serve a cert the
// adopted cluster CA cannot verify, and the node's own k3s agent then
// loops forever on "CA cert validation failed" against 127.0.0.1:6443
// without ever registering. The directory itself is kept so its 0700
// mode survives.
//
// The kubeconfigs go with it. They embed the CA being retired, so a
// surviving copy describes an authority that no longer exists — and
// because WaitKubeconfig only waits for the file to be *present*, a
// leftover satisfies it instantly and the readiness client is built
// against the dead CA. Every call then fails the TLS handshake while the
// apiserver is perfectly healthy, which looks like an unresponsive node
// rather than a stale client. Observed 2026-08-05 on edge-dev2: the
// pre-join kubeconfig from 12:38:28 was adopted at 12:48:55, k3s wrote
// the real one at 12:48:57, and the join then burned 5m13s before the
// join watchdog rebooted a node that had joined correctly. Deleting
// them here means the only kubeconfig that can appear is the new one.
//
// KubeconfigCopy matters as much as the original: it is what pillar
// reads (kubeapi.EVEkubeConfigFile), so a stale copy propagates the
// retired CA into zedkube, whose node drain/delete then fails the same
// way.
//
// Missing paths are silently ignored. Errors are joined and returned
// together so one undeletable file does not hide the rest.
// derivedKubeconfigs are removed after the TLS material they describe.
func removeServerTLSDir(tlsRoot, ipsecPSK string, derivedKubeconfigs ...string) error {
	var joined error
	entries, err := os.ReadDir(tlsRoot)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// Nothing to clear; still drop the PSK below.
	case err != nil:
		joined = fmt.Errorf("read %s: %w", tlsRoot, err)
	default:
		for _, e := range entries {
			p := filepath.Join(tlsRoot, e.Name())
			if err := os.RemoveAll(p); err != nil {
				log.Printf("warning: remove %s: %v", p, err)
				joined = errors.Join(joined, fmt.Errorf("remove %s: %w", p, err))
			}
		}
	}

	if err := removeIfExists(ipsecPSK); err != nil {
		log.Printf("warning: remove %s: %v", ipsecPSK, err)
		joined = errors.Join(joined, fmt.Errorf("remove %s: %w", ipsecPSK, err))
	}

	for _, kubeconfig := range derivedKubeconfigs {
		if err := removeIfExists(kubeconfig); err != nil {
			log.Printf("warning: remove %s: %v", kubeconfig, err)
			joined = errors.Join(joined,
				fmt.Errorf("remove %s: %w", kubeconfig, err))
			continue
		}
		log.Printf("removed kubeconfig %s — it described the retired CA",
			kubeconfig)
	}
	return joined
}
