// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package localcommand

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/lf-edge/eve-api/go/profile"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	// sigHandlerURLPath is the REST API path for the long-lived LPS signaling
	// stream. LPS writes a NDJSON sequence of profile.Signal messages,
	// each listing LPS endpoints with pending configuration changes.
	sigHandlerURLPath = "/api/v1/signal"

	// sigHandlerKeepAlivePeriod is the TCP keepalive interval applied to
	// the signal connection. This is the sole mechanism for detecting a
	// silently broken peer; there is no application-layer heartbeat.
	sigHandlerKeepAlivePeriod = 60 * time.Second

	// sigHandlerBackoffInitial is the initial delay after a failed
	// reconnect attempt against every known LPS address.
	sigHandlerBackoffInitial = 1 * time.Second
	// sigHandlerBackoffMax caps the exponential backoff.
	sigHandlerBackoffMax = 30 * time.Second

	// sigHandlerThrottleInterval is the delay used after LPS returns 404,
	// meaning it does not implement the endpoint. The signal stream is
	// optional, so we keep checking occasionally in case LPS starts
	// supporting it later without requiring a device reconfiguration.
	sigHandlerThrottleInterval = 1 * time.Hour

	// sigHandlerLineBufMax caps the maximum line length accepted from LPS.
	// Signal payloads are tiny (a handful of enum values); the limit is
	// defensive against a misbehaving peer streaming long garbage.
	sigHandlerLineBufMax = 64 * 1024

	// sigHandlerRateInterval and sigHandlerRateBurst bound how frequently
	// incoming signals can trigger polls. The limit is per Signal message
	// (Allow() is called once per message, not once per listed endpoint), so
	// a single message listing all 6 endpoints consumes only one token.
	// Config changes are human-submitted and expected to be infrequent;
	// excess signals are dropped. The periodic polling fallback guarantees
	// eventual consistency.
	sigHandlerRateInterval = 3 * time.Second
	sigHandlerRateBurst    = 3

	// sigHandlerMaxEndpoints is the maximum number of pending-change entries
	// accepted in a single Signal message. A well-behaved LPS sends at most
	// one entry per known endpoint; far more entries indicate a buggy or
	// malicious peer and the message is dropped.
	sigHandlerMaxEndpoints = 32

	// sigHandlerLogLineMax is the maximum number of bytes of a malformed
	// signal line included in a log message.
	sigHandlerLogLineMax = 256
)

// sigHandlerOutcome describes the result of a single attempt to open a
// signal stream.
type sigHandlerOutcome int

const (
	// sigHandlerOutcomeOpened means the stream was successfully opened; the
	// caller receives the HTTP response and the cancel function for the
	// stream's context, and is responsible for reading and closing the body.
	sigHandlerOutcomeOpened sigHandlerOutcome = iota
	// sigHandlerOutcomeNoConfig means LPS is not configured or no apps
	// running LPS have been discovered yet. The outer loop parks on
	// restartSigHandlerCh until a change occurs.
	sigHandlerOutcomeNoConfig
	// sigHandlerOutcomeNotFound means LPS returned 404: the endpoint is not
	// implemented. The outer loop throttles reconnect attempts.
	sigHandlerOutcomeNotFound
	// sigHandlerOutcomeFailed means every known LPS address failed to produce
	// a usable response (dial error, non-200/404 status, etc.). The outer
	// loop backs off before retrying.
	sigHandlerOutcomeFailed
	// sigHandlerOutcomePaused means the attempt was aborted because the
	// LocalCmdAgent tasks were paused (e.g., UpdateLpsConfig is applying
	// new config). The outer loop retries shortly.
	sigHandlerOutcomePaused
)

// initializeSigHandler allocates the rate limiter and restart channel used
// by the Signal handler. The goroutine itself is launched later from RunTasks.
func (lc *LocalCmdAgent) initializeSigHandler() {
	lc.sigHandlerLimiter = rate.NewLimiter(
		rate.Every(sigHandlerRateInterval), sigHandlerRateBurst)
	lc.restartSigHandlerCh = make(chan struct{}, 1)
}

// runSigHandlerTask maintains a long-lived connection to the LPS
// /api/v1/signal endpoint and translates incoming Signal messages into
// immediate triggers of the appropriate per-endpoint poller. The stream is
// a latency optimization only; periodic polling by the other tasks remains
// the correctness guarantee.
//
// The goroutine does NOT register with the pillar watchdog — a legitimately
// long blocking Read on the stream must not be able to trigger a device
// reboot. Participation in taskControl is limited to the connection-open
// phase (see openSigHandlerStream); the subsequent body read runs without
// holding the task lock, so it does not block pause() of other tasks.
func (lc *LocalCmdAgent) runSigHandlerTask() {
	lc.Log.Functionf("%s: runSigHandlerTask: starting", logPrefix)
	backoff := sigHandlerBackoffInitial
	for {
		resp, cancel, outcome := lc.openSigHandlerStream()

		switch outcome {
		case sigHandlerOutcomeOpened:
			// Read the NDJSON stream without the task lock held.
			lc.readSigHandlerStream(resp.Body)
			resp.Body.Close()
			cancel()
			lc.sigHandlerMx.Lock()
			lc.sigHandlerCancel = nil
			lc.sigHandlerMx.Unlock()
			backoff = sigHandlerBackoffInitial
		case sigHandlerOutcomeNoConfig:
			// Park until LPS is configured or discovered.
			<-lc.restartSigHandlerCh
			backoff = sigHandlerBackoffInitial
		case sigHandlerOutcomePaused:
			// Tasks are paused (config likely just changed); retry shortly.
			lc.waitUnlessSigHandlerRestarted(sigHandlerBackoffInitial)
		case sigHandlerOutcomeNotFound:
			// LPS does not implement the endpoint; throttle reconnects.
			lc.waitUnlessSigHandlerRestarted(sigHandlerThrottleInterval)
			backoff = sigHandlerBackoffInitial
		case sigHandlerOutcomeFailed:
			// Every known address failed; back off.
			lc.waitUnlessSigHandlerRestarted(backoff)
			backoff *= 2
			if backoff > sigHandlerBackoffMax {
				backoff = sigHandlerBackoffMax
			}
		}
	}
}

// openSigHandlerStream snapshots the LPS configuration under the task
// control read lock, then opens a long-lived HTTP GET connection to
// /api/v1/signal on the first reachable LPS address. The lock is held only
// for the brief snapshot + connection-initiation phase (with the dial
// itself released via runInterruptible so it does not block pause()); it
// is released before returning so the caller can read the streaming body
// without blocking pause() of other tasks.
//
// On sigHandlerOutcomeOpened, the caller must:
//   - close resp.Body when done reading the stream,
//   - invoke cancel() to release the stream's context.
//
// For any other outcome, both returned values are nil.
func (lc *LocalCmdAgent) openSigHandlerStream() (
	*http.Response, context.CancelFunc, sigHandlerOutcome) {
	if paused := lc.tc.startTask(); paused {
		return nil, nil, sigHandlerOutcomePaused
	}
	defer lc.tc.endTask()

	if lc.lpsURL == nil {
		return nil, nil, sigHandlerOutcomeNoConfig
	}
	if lc.lpsAddresses.empty() {
		lc.Log.Functionf(
			"%s: openSigHandlerStream: no apps running LPS have been discovered yet",
			logPrefix)
		return nil, nil, sigHandlerOutcomeNoConfig
	}

	for intf, addrs := range lc.lpsAddresses.addrsByIface {
		for _, addr := range addrs {
			fullURL := addr.destURL.String() + sigHandlerURLPath
			ctx, cancel := context.WithCancel(context.Background())

			var (
				resp    *http.Response
				openErr error
			)
			wasPaused := lc.tc.runInterruptible(func() {
				resp, openErr = lc.CtrlClient.OpenLocalStream(
					ctx, fullURL, intf, addr.sourceIP, sigHandlerKeepAlivePeriod)
			})
			if wasPaused {
				if resp != nil {
					resp.Body.Close()
				}
				cancel()
				lc.Log.Functionf(
					"%s: openSigHandlerStream: discarded due to task pause",
					logPrefix)
				return nil, nil, sigHandlerOutcomePaused
			}
			if openErr != nil {
				cancel()
				lc.Log.Tracef("%s: signal: OpenLocalStream(%s) failed: %v",
					logPrefix, fullURL, openErr)
				continue
			}

			switch resp.StatusCode {
			case http.StatusOK:
				// Register cancel so restartSigHandler can interrupt the read.
				lc.sigHandlerMx.Lock()
				lc.sigHandlerCancel = cancel
				lc.sigHandlerMx.Unlock()
				lc.Log.Noticef("%s: signal: stream opened to %s",
					logPrefix, fullURL)
				return resp, cancel, sigHandlerOutcomeOpened
			case http.StatusNotFound:
				resp.Body.Close()
				cancel()
				lc.Log.Noticef(
					"%s: signal: LPS does not implement the endpoint (404); "+
						"throttling reconnect attempts", logPrefix)
				return nil, nil, sigHandlerOutcomeNotFound
			default:
				resp.Body.Close()
				cancel()
				lc.Log.Warnf("%s: signal: unexpected status %d from %s",
					logPrefix, resp.StatusCode, fullURL)
				continue
			}
		}
	}
	return nil, nil, sigHandlerOutcomeFailed
}

// readSigHandlerStream reads NDJSON-framed Signal messages from the given
// body until the stream ends (EOF, cancellation, or I/O error). Malformed
// lines and blank lines are tolerated.
func (lc *LocalCmdAgent) readSigHandlerStream(body io.Reader) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 1024), sigHandlerLineBufMax)
	unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var sig profile.Signal
		if err := unmarshaler.Unmarshal(line, &sig); err != nil {
			logLine := line
			if len(logLine) > sigHandlerLogLineMax {
				logLine = logLine[:sigHandlerLogLineMax]
			}
			lc.Log.Warnf("%s: signal: decode failed: %v (line=%q)",
				logPrefix, err, logLine)
			continue
		}
		lc.handleSignal(&sig)
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, context.Canceled) {
			lc.Log.Noticef("%s: signal: stream closed (restart requested)",
				logPrefix)
		} else {
			lc.Log.Noticef("%s: signal: stream ended: %v", logPrefix, err)
		}
	}
}

// handleSignal dispatches the endpoints listed in a received Signal message
// to the corresponding per-endpoint trigger. Incoming signals are
// rate-limited to bound the cost of excessive traffic from a buggy or
// malicious LPS; dropped signals are safe because the periodic polling
// fallback guarantees eventual consistency.
//
// Note: the triggered tickers use tickNow(), which short-circuits silently
// when a ticker is throttled (e.g., after a 404 from the same endpoint).
// That is the desired behavior -- a Signal claiming an endpoint that LPS
// has previously declined to implement should not lift its throttle.
func (lc *LocalCmdAgent) handleSignal(sig *profile.Signal) {
	if n := len(sig.GetPendingChanges()); n > sigHandlerMaxEndpoints {
		lc.Log.Warnf("%s: signal: dropped (too many endpoints: %d > %d)",
			logPrefix, n, sigHandlerMaxEndpoints)
		return
	}
	if !lc.sigHandlerLimiter.Allow() {
		lc.Log.Warnf("%s: signal: dropped by rate limit (%d endpoints)",
			logPrefix, len(sig.GetPendingChanges()))
		return
	}
	for _, ep := range sig.GetPendingChanges() {
		switch ep {
		case profile.ConfigEndpoint_CONFIG_ENDPOINT_LOCAL_PROFILE:
			lc.TriggerProfileGET()
		case profile.ConfigEndpoint_CONFIG_ENDPOINT_RADIO:
			lc.TriggerRadioPOST()
		case profile.ConfigEndpoint_CONFIG_ENDPOINT_APP_INFO:
			lc.TriggerAppInfoPOST()
		case profile.ConfigEndpoint_CONFIG_ENDPOINT_APP_BOOT_INFO:
			lc.TriggerAppBootInfoPOST()
		case profile.ConfigEndpoint_CONFIG_ENDPOINT_DEV_INFO:
			lc.TriggerDevInfoPOST()
		case profile.ConfigEndpoint_CONFIG_ENDPOINT_NETWORK:
			lc.TriggerNetworkPOST()
		default:
			lc.Log.Tracef("%s: signal: ignoring unknown endpoint: %v",
				logPrefix, ep)
		}
	}
}

// restartSigHandler cancels any in-flight signal stream and wakes the
// Signal handler goroutine if it is parked or waiting. Called from
// UpdateLpsConfig whenever the LPS address changes so the stream is
// promptly redirected to the new server.
func (lc *LocalCmdAgent) restartSigHandler() {
	lc.sigHandlerMx.Lock()
	cancel := lc.sigHandlerCancel
	lc.sigHandlerMx.Unlock()
	if cancel != nil {
		cancel()
	}
	// Non-blocking notify: wakes the goroutine if it is currently parked
	// on restartSigHandlerCh. A stale notification sitting in the buffer
	// is harmless -- it just skips one backoff or throttle cycle.
	select {
	case lc.restartSigHandlerCh <- struct{}{}:
	default:
	}
}

// waitUnlessSigHandlerRestarted blocks for up to d, returning early if
// restartSigHandler fires.
func (lc *LocalCmdAgent) waitUnlessSigHandlerRestarted(d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-lc.restartSigHandlerCh:
	}
}
