// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// readBpduGuard reads the BPDU guard sysfs flag for a named bridge port.
// Returns "0", "1", or "" if the path cannot be read.
func readBpduGuard(device *evetest.EdgeDevice, bridgeName, portName string,
	sshTimeout time.Duration) string {
	path := "/sys/class/net/" + bridgeName + "/brif/" + portName + "/bpdu_guard"
	output, _, err := device.RunShellScript("cat "+path, sshTimeout, 0)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(output)
}

// niHasError is a matchers.SatisfyPredicate StopIf callback: it stops an
// Eventually early if the network instance has reached the ERROR state,
// instead of waiting out the full timeout.
func niHasError(info *eveinfo.ZInfoNetworkInstance) (string, bool) {
	stop := info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ERROR
	if stop {
		return "Network instance is in error state", true
	}
	return "", false
}

// expectNIInfo waits until the network instance info satisfies matcher, and
// returns the info that did. It first checks last, the newest info an earlier
// wait already took from updates (nil if none): EVE publishes network instance
// info only when the network instance's status changes, so the state waited for
// can be in that message already, with no further message to come.
func expectNIInfo(t *WithT, updates <-chan *eveinfo.ZInfoNetworkInstance,
	last *eveinfo.ZInfoNetworkInstance, timeout time.Duration,
	matcher types.GomegaMatcher) *eveinfo.ZInfoNetworkInstance {
	if last != nil {
		// Match also returns an error when a StopIf fires; Expect reports it.
		if matched, err := matcher.Match(last); matched || err != nil {
			t.Expect(last).To(matcher)
			return last
		}
	}
	var info *eveinfo.ZInfoNetworkInstance
	t.Eventually(updates, timeout).Should(Receive(&info, matcher))
	return info
}

// appHasError is a matchers.SatisfyPredicate StopIf callback: it stops an
// Eventually early if the application instance has reached the ERROR state,
// instead of waiting out the full timeout.
func appHasError(info *eveinfo.ZInfoApp) (string, bool) {
	stop := info.State == eveinfo.ZSwState_ERROR
	if stop {
		return "Application instance is in error state", true
	}
	return "", false
}

// contentTreeTracker follows the info messages of many content trees and
// keeps the latest one per tree, so that a test deploying many content trees
// at once can look at their overall state without draining the watch channels
// itself.
type contentTreeTracker struct {
	mu     sync.Mutex
	latest map[uuid.UUID]*eveinfo.ZInfoContentTree
	stops  []func()
}

// trackContentTrees starts following the info of the given content trees.
// Call stop when done.
func trackContentTrees(device *evetest.EdgeDevice, ctUUIDs []uuid.UUID) *contentTreeTracker {
	tracker := &contentTreeTracker{
		latest: make(map[uuid.UUID]*eveinfo.ZInfoContentTree, len(ctUUIDs)),
	}
	for _, ctUUID := range ctUUIDs {
		updates, stop := device.WatchContentTreeInfo(ctUUID)
		tracker.stops = append(tracker.stops, stop)
		go func(ctUUID uuid.UUID) {
			for info := range updates {
				tracker.mu.Lock()
				tracker.latest[ctUUID] = info
				tracker.mu.Unlock()
			}
		}(ctUUID)
	}
	return tracker
}

// get returns the latest reported info of the content tree, or nil if the
// device has not reported it yet.
func (tracker *contentTreeTracker) get(ctUUID uuid.UUID) *eveinfo.ZInfoContentTree {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return tracker.latest[ctUUID]
}

// stop ends all the watches started by trackContentTrees.
func (tracker *contentTreeTracker) stop() {
	for _, stop := range tracker.stops {
		stop()
	}
}

// contentTreeHasError reports whether the latest report of the content tree
// carries an error, i.e. whether its download has failed and parked.
func contentTreeHasError(info *eveinfo.ZInfoContentTree) bool {
	return info.GetErr().GetDescription() != ""
}

// contentTreeIsLoaded reports whether all blobs of the content tree have been
// downloaded, verified and loaded into the content-addressable store. EVE
// reports its internal LOADED state as DELIVERED in the API (see
// SwState.ZSwState in pillar), so both are accepted.
func contentTreeIsLoaded(info *eveinfo.ZInfoContentTree) bool {
	if info == nil {
		return false
	}
	return info.GetState() == eveinfo.ZSwState_DELIVERED ||
		info.GetState() == eveinfo.ZSwState_LOADED
}

// describeContentTree renders the state a content tree is in, e.g.
// "DOWNLOAD_STARTED at 0%", with the error description appended when the
// content tree reports one.
func describeContentTree(info *eveinfo.ZInfoContentTree) string {
	if info == nil {
		return "not reported yet"
	}
	desc := fmt.Sprintf("%s at %d%%", info.GetState(), info.GetProgressPercentage())
	if errDesc := info.GetErr().GetDescription(); errDesc != "" {
		desc += ", error: " + errDesc
	}
	return desc
}

// logDeviceObjectStates logs how many content trees, blobs and downloads the
// device itself currently holds in each state. It tells a device that is still
// working, or has finished, apart from one whose reports have not reached the
// controller yet: every state change is one info message, sent one after
// another, and with hundreds of objects the last report can trail the device
// by minutes.
func logDeviceObjectStates(device *evetest.EdgeDevice) {
	log := evetest.Logger()
	const script = `for d in /run/volumemgr/ContentTreeStatus /run/volumemgr/BlobStatus \
	/run/downloader/DownloaderStatus; do
	echo "== $d"
	cat "$d"/*.json 2>/dev/null | grep -oE '"State": *[0-9]+' | grep -oE '[0-9]+$' | sort | uniq -c
done`
	out, _, err := device.RunShellScript(script, time.Minute, 0)
	if err != nil {
		log.Warnf("Cannot summarize the device's object states: %v", err)
		return
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		switch {
		case len(fields) == 2 && fields[0] == "==":
			log.Infof("device view of %s:", fields[1])
		case len(fields) == 2:
			state, err := strconv.Atoi(fields[1])
			if err != nil {
				continue
			}
			log.Infof("  %s objects in state %s", fields[0], pillartypes.SwState(state))
		}
	}
}

// logDownloaderView logs what the downloader microservice itself records for
// up to maxBlobs of the blobs listed in namesBySHA (state, downloaded bytes,
// retries, error). It is meant for diagnosing a download that never finished:
// a blob stuck at zero bytes with zero retries and no error is a download the
// downloader has stopped working on without noticing, whereas a slow or
// failing download shows progress, retries or an error.
func logDownloaderView(device *evetest.EdgeDevice, namesBySHA map[string]string,
	maxBlobs int) {
	log := evetest.Logger()
	logged := 0
	for sha256Hex, name := range namesBySHA {
		if logged == maxBlobs {
			break
		}
		logged++
		data, err := device.ReadFile("/run/downloader/DownloaderStatus/" +
			strings.ToLower(sha256Hex) + ".json")
		if err != nil {
			log.Warnf("Cannot read the DownloaderStatus of %s: %v", name, err)
			continue
		}
		var status pillartypes.DownloaderStatus
		if err := json.Unmarshal(data, &status); err != nil {
			log.Warnf("Cannot parse the DownloaderStatus of %s: %v", name, err)
			continue
		}
		log.Infof("downloader view of %s: state=%s progress=%d%% bytes=%d/%d "+
			"retries=%d error=%q", name, status.State, status.Progress,
			status.CurrentSize, status.TotalSize, status.RetryCount, status.Error)
	}
}

// recordingDatastore is an HTTP datastore run by the test itself, which
// records every request it receives, so that a test can tell how often, and
// with which URL, a device has asked for a file; evetest's built-in image
// server keeps no such record. It listens on a port of its own on the image
// server's address, which a device reaches the same way as the image server,
// and serves its files from memory, whatever query string a request carries.
type recordingDatastore struct {
	listener net.Listener
	server   *http.Server
	logf     func(format string, args ...interface{})

	mu    sync.Mutex
	files map[string][]byte
	// requests holds, per file name, the requests received for that file,
	// oldest first, each as "<method> <request URI>".
	requests map[string][]string
}

// startRecordingDatastore starts a recordingDatastore on a free port of the
// image server's address. Call stop when done.
func startRecordingDatastore(t *WithT) *recordingDatastore {
	listener, err := net.Listen("tcp4",
		net.JoinHostPort(evetest.GetImageServerIPv4().String(), "0"))
	t.Expect(err).ToNot(HaveOccurred(), "failed to start the recording datastore")
	datastore := &recordingDatastore{
		listener: listener,
		logf:     evetest.Logger().Infof,
		files:    make(map[string][]byte),
		requests: make(map[string][]string),
	}
	datastore.server = &http.Server{
		Handler:           datastore,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		_ = datastore.server.Serve(listener)
	}()
	datastore.logf("Recording datastore listening on http://%s/", listener.Addr())
	return datastore
}

// stop shuts the datastore down, dropping any connection still open.
func (datastore *recordingDatastore) stop() {
	_ = datastore.server.Close()
}

// port returns the TCP port the datastore listens on.
func (datastore *recordingDatastore) port() uint16 {
	return uint16(datastore.listener.Addr().(*net.TCPAddr).Port)
}

// addRandomFile makes the datastore serve a file of sizeBytes random bytes
// under the given name, and returns the hex-encoded SHA256 of its content
// (for ImageSHA256). See evetest.CreateRandomImageFile for why the content is
// random.
func (datastore *recordingDatastore) addRandomFile(t *WithT, name string,
	sizeBytes uint64) (sha256Hex string) {
	content := make([]byte, sizeBytes)
	_, err := rand.Read(content)
	t.Expect(err).ToNot(HaveOccurred(), "failed to generate random content for %s", name)
	sum := sha256.Sum256(content)
	datastore.mu.Lock()
	datastore.files[name] = content
	datastore.mu.Unlock()
	return hex.EncodeToString(sum[:])
}

// requestsFor returns the requests received so far for the file with the
// given name, oldest first, each as "<method> <request URI>", e.g.
// "GET /image.bin?sig=token".
func (datastore *recordingDatastore) requestsFor(name string) []string {
	datastore.mu.Lock()
	defer datastore.mu.Unlock()
	return append([]string(nil), datastore.requests[name]...)
}

// ServeHTTP records the request and serves the requested file.
func (datastore *recordingDatastore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	request := r.Method + " " + r.URL.RequestURI()
	datastore.mu.Lock()
	datastore.requests[name] = append(datastore.requests[name], request)
	content, found := datastore.files[name]
	datastore.mu.Unlock()
	datastore.logf("Recording datastore received %q from %s", request, r.RemoteAddr)
	if !found {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(content))
}

// appHasIP returns true if the application reports the given IP address on any
// of its network adapters.
func appHasIP(info *eveinfo.ZInfoApp, ip string) bool {
	for _, adapter := range info.Network {
		for _, adapterIP := range adapter.IPAddrs {
			if adapterIP == ip {
				return true
			}
		}
	}
	return false
}

// startSwitchNITraffic starts a background script inside the application which
// mimics an app that replaces the IP address received over DHCP with a static
// one (as cloud-init does) and then generates traffic that EVE snoops on a Switch NI:
//   - an ARP request (sent from the static IP) every arpPeriod, which is how EVE
//     learns the static IP of the app,
//   - a steady stream of UDP packets to port 53, which EVE captures as DNS traffic
//     and which is intended to keep the packet capture busy.
//
// The script is detached, therefore the call returns before the DHCP address
// is replaced and the app stops being reachable over it.
func startSwitchNITraffic(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID,
	staticIP, gatewayIP, dnsIP string, arpPeriod time.Duration) {
	script := fmt.Sprintf(`cat > /tmp/traffic.sh <<'SCRIPT'
#!/bin/bash
IF=$(ip -o route get %[2]s | sed -n 's/.* dev \([^ ]*\).*/\1/p')
sleep 3
ip addr flush dev "$IF"
ip addr add %[1]s/24 dev "$IF"
ip route add default via %[2]s dev "$IF"
(
  exec 3<>/dev/udp/%[3]s/53
  while true; do echo x >&3; sleep 0.005; done
) &
while true; do
  ip neigh flush dev "$IF"
  ping -c1 -W1 -I %[1]s %[2]s >/dev/null 2>&1
  sleep %[4]d
done
SCRIPT
chmod +x /tmp/traffic.sh
nohup /tmp/traffic.sh >/tmp/traffic.log 2>&1 </dev/null &
`, staticIP, gatewayIP, dnsIP, int(arpPeriod.Seconds()))
	_, _, err := device.RunShellScriptInsideApp(appUUID, evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}, script, 20*time.Second, 0)
	t.Expect(err).ToNot(HaveOccurred())
}

// generateUnrelatedCA returns a freshly generated self-signed RSA CA
// (certificate and PKCS#1 private key, both PEM) that has no relation to any CA
// the test network was built with. It is used to make an authenticator (RADIUS
// server) trust only a CA that did not issue the device's certificate.
func generateUnrelatedCA(commonName string) (certPEM, keyPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"evetest"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPEM, keyPEM, nil
}
