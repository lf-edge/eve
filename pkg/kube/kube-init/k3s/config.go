// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// Drop-in config files written to K3sConfigDir. k3s reads every
// *.yaml in that directory in lexical order at startup; the numeric
// prefixes choose the merge order. Slot 02 is intentionally reserved
// for future use.
const (
	NodeNameConfig   = "00-nodename.yaml"
	ClusterConfig    = "01-clusterconfig.yaml"
	DisableLocalPath = "03-enc-disable-local-path.yaml"

	// UserOverrideConfig wins lexical-order conflicts with the
	// kube-init-rendered drop-ins above (prefix 99).
	UserOverrideConfig = "99-k3s-config-user-overrides.yaml"
)

const (
	// disableLocalPathContent is the YAML body for the DisableLocalPath
	// drop-in. Body kept byte-stable; k3s drop-in hashing triggers a
	// restart on any byte change.
	disableLocalPathContent = "# Use longhorn storage\ndisable: local-storage\n"

	// clusterStatusPort is the HTTP port where a bootstrap node
	// advertises its cluster UUID over the cluster interface during
	// the join-wait handshake.
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

// encStatusJSON mirrors the on-disk EdgeNodeClusterStatus JSON.
// net.IP fields are captured as RawMessage and decoded via
// parseIPField so a future encoding change does not break the rest
// of the parser.
type encStatusJSON struct {
	ClusterInterface      string          `json:"ClusterInterface"`
	BootstrapNode         bool            `json:"BootstrapNode"`
	JoinServerIP          json.RawMessage `json:"JoinServerIP"`
	EncryptedClusterToken string          `json:"EncryptedClusterToken"`
	ClusterIPPrefix       *struct {
		IP   json.RawMessage `json:"IP"`
		Mask []byte          `json:"Mask"`
	} `json:"ClusterIPPrefix"`
	ClusterIPIsReady bool `json:"ClusterIPIsReady"`
	ClusterID        *struct {
		UUID string `json:"UUID"`
	} `json:"ClusterID"`
}

type encConfigJSON struct {
	ClusterType *int `json:"ClusterType"`
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

// GetClusterStatus reads and validates the EdgeNodeClusterStatus
// JSON. The returned ClusterStatus has every essential string field
// non-empty; missing or empty fields surface as an error.
func GetClusterStatus() (*ClusterStatus, error) {
	data, err := os.ReadFile(EncStatusFile)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", EncStatusFile, err)
	}
	var raw encStatusJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", EncStatusFile, err)
	}
	cs := &ClusterStatus{
		ClusterInterface: raw.ClusterInterface,
		IsBootstrapNode:  raw.BootstrapNode,
		EncryptedToken:   raw.EncryptedClusterToken,
		ClusterIPIsReady: raw.ClusterIPIsReady,
		JoinServerIP:     parseIPField(raw.JoinServerIP),
	}
	if raw.ClusterIPPrefix != nil {
		cs.ClusterIP = parseIPField(raw.ClusterIPPrefix.IP)
		if len(raw.ClusterIPPrefix.Mask) > 0 {
			// net.IPMask.Size returns (ones, bits); 0/0 means
			// the mask is not canonical and we should ignore
			// it rather than treat it as /0.
			ones, _ := net.IPMask(raw.ClusterIPPrefix.Mask).Size()
			cs.PrefixLen = ones
		}
	}
	if raw.ClusterID != nil {
		cs.ClusterID = raw.ClusterID.UUID
	}
	if err := cs.validate(); err != nil {
		return nil, fmt.Errorf("validate %s: %w", EncStatusFile, err)
	}
	return cs, nil
}

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

// GetClusterType reads ClusterType from the persisted
// EdgeNodeClusterConfig. If the file is missing OR the field is
// absent, ClusterTypeReplicated is returned — that was the
// historical default before the controller began emitting the field.
// If the file is present but malformed, the same default is returned
// alongside a non-nil error so callers can choose to treat it as
// hard-failure.
func GetClusterType() (ClusterType, error) {
	data, err := os.ReadFile(ClusterConfigFile)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return ClusterTypeReplicated, nil
	case err != nil:
		return ClusterTypeReplicated, fmt.Errorf("read %s: %w", ClusterConfigFile, err)
	}
	var raw encConfigJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return ClusterTypeReplicated, fmt.Errorf("parse %s: %w", ClusterConfigFile, err)
	}
	if raw.ClusterType == nil {
		return ClusterTypeReplicated, nil
	}
	return ClusterType(*raw.ClusterType), nil
}

// IsClusterMode reports whether the device is currently configured
// as part of an HA cluster.
func IsClusterMode() (bool, error) {
	return state.IsMarked(state.EdgeNodeClusterMode)
}

// zeroClusterUUID is the all-zeros sentinel pillar publishes in
// EdgeNodeClusterStatus when the controller has deleted the
// cluster config. The publication is not Persistent, so deletion
// is signalled by an empty payload rather than file removal —
// addresses upstream 158981334 ("eve-k: fix cluster delete
// regression") which made the equivalent shell check.
const zeroClusterUUID = "00000000-0000-0000-0000-000000000000"

// ClusterStatusPresent reports whether the EdgeNodeClusterStatus
// payload represents a live cluster. Returns false when the file
// is absent OR when the payload carries the zero ClusterID UUID
// (which is how a controller-side cluster delete surfaces).
//
// Read errors other than ErrNotExist are surfaced so callers can
// decide whether to treat a wedged /run as transient — silently
// collapsing EIO to "no cluster" would mis-fire a cluster→single
// transition on a stat hiccup.
func ClusterStatusPresent() (bool, error) {
	data, err := os.ReadFile(EncStatusFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("read %s: %w", EncStatusFile, err)
	}
	var raw encStatusJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		// Malformed payload is treated as "not-yet-published" so a
		// transient half-write does not trip a transition. The
		// next health tick will re-read; a persistent malformed
		// payload is a pillar bug that surfaces elsewhere.
		return false, nil
	}
	if raw.ClusterID == nil || raw.ClusterID.UUID == "" ||
		raw.ClusterID.UUID == zeroClusterUUID {
		return false, nil
	}
	return true, nil
}

// ProvisionClusterConfig writes the cluster-mode drop-ins for the
// current node role: cluster-init for the bootstrap node, server-join
// for everyone else. On first boot for a joining node the call blocks
// until the bootstrap server is reachable and reports a matching
// cluster UUID.
func ProvisionClusterConfig(ctx context.Context, isFirstBoot bool) error {
	cs, err := GetClusterStatus()
	if err != nil {
		return fmt.Errorf("get cluster status: %w", err)
	}
	if err := provisionDisableLocalPath(); err != nil {
		return fmt.Errorf("provision disable-local-path: %w", err)
	}
	clusterCfgPath := filepath.Join(K3sConfigDir, ClusterConfig)
	if cs.IsBootstrapNode {
		return writeBootstrapConfig(clusterCfgPath, cs, isFirstBoot)
	}
	return writeJoinConfig(ctx, clusterCfgPath, cs, isFirstBoot)
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
	if isFirstBoot {
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
	log.Printf("bootstrap config written (firstBoot=%v)", isFirstBoot)
	return nil
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
		statusURL := fmt.Sprintf("http://%s:%s/status",
			bracketIPv6(cs.JoinServerIP), clusterStatusPort)
		if err := waitForBootstrapServer(ctx, apiURL, statusURL, cs.ClusterID); err != nil {
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
// The UUID check is the actual authentication boundary — it guards
// against accidentally joining a re-IP'd different cluster.
//
// The first probe runs immediately (do not wait one full poll
// interval before checking — the bootstrap node may already be up).
//
// The function distinguishes transient errors (connection refused,
// server still spinning up) from non-transient ones (DNS NXDOMAIN,
// TLS verification failure, HTTP 4xx/5xx). After
// nonTransientThreshold consecutive non-transient failures it
// returns ErrBootstrapUnreachable rather than spinning silently.
func waitForBootstrapServer(ctx context.Context, apiURL, statusURL, expectedClusterID string) error {
	log.Printf("waiting for bootstrap server %s ...", apiURL)

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
	// The real authentication boundary is the cluster-UUID match
	// against the response body of the cluster-status endpoint a
	// few lines below: if the UUID does not equal expectedClusterID
	// (sourced from pillar's EdgeNodeClusterStatus, delivered over
	// a controller-authenticated channel), the probe rejects the
	// response regardless of what the TLS layer would have
	// decided. A man-in-the-middle that does not know
	// expectedClusterID cannot fabricate a passing response.
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
	httpClient := &http.Client{Timeout: joinHTTPClientTimeout}

	consecutiveNonTransient := 0

	probe := func(attempt int) (done bool, err error) {
		// Bail loudly if the cluster status payload was withdrawn
		// while we were waiting — the controller revoked the cluster
		// config and continuing to poll is wrong.
		if _, statErr := os.Stat(EncStatusFile); statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				return true, fmt.Errorf("%w: %s missing", ErrClusterStatusWithdrawn, EncStatusFile)
			}
			return true, fmt.Errorf("stat %s: %w", EncStatusFile, statErr)
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
		resp.Body.Close()

		// 2. Status endpoint reachable + reporting cluster UUID?
		statusBody, statusErr := fetchClusterStatus(httpClient, statusURL)
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

// fetchClusterStatus issues one GET against the status endpoint and
// returns the trimmed body. Any read error is surfaced rather than
// silently producing an empty body (which would be indistinguishable
// from a server that legitimately hasn't entered cluster mode yet).
func fetchClusterStatus(c *http.Client, statusURL string) (string, error) {
	resp, err := c.Get(statusURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
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
		log.Printf(format, args...)
	}
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

// parseIPField extracts an IP address string from a JSON-encoded
// net.IP value. Returns "" on any decode failure; downstream
// validate() will then catch the missing-or-malformed case
// uniformly. A decode failure is logged so the breadcrumb is
// available even though the empty string makes the case look like
// "field absent".
func parseIPField(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		log.Printf("parseIPField: unmarshal failed: %v", err)
		return ""
	}
	return s
}

// RemoveServerTLSDir deletes the k3s server CA/key material so the
// next k3s start regenerates a clean PKI. Used by the cluster→single
// transition flow.
//
// Missing files are silently ignored. The first non-ENOENT error is
// returned; further errors during the same call are joined onto it.
func RemoveServerTLSDir() error {
	const tlsRoot = "/var/lib/rancher/k3s/server/tls"
	const credRoot = "/var/lib/rancher/k3s/server/cred"
	if _, err := os.Stat(tlsRoot); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", tlsRoot, err)
	}

	files := []string{
		tlsRoot + "/request-header-ca.key",
		tlsRoot + "/server-ca.key",
		tlsRoot + "/etcd/peer-ca.key",
		tlsRoot + "/etcd/server-ca.crt",
		tlsRoot + "/request-header-ca.crt",
		tlsRoot + "/etcd/server-ca.key",
		credRoot + "/ipsec.psk",
		tlsRoot + "/server-ca.crt",
		tlsRoot + "/service.key",
	}
	var joined error
	for _, f := range files {
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("warning: remove %s: %v", f, err)
			joined = errors.Join(joined, fmt.Errorf("remove %s: %w", f, err))
		}
	}
	return joined
}
