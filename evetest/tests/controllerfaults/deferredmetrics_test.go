// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// What EVE tells the controller about the reports it is holding back.

package controllerfaults_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	evemetrics "github.com/lf-edge/eve-api/go/metrics"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// How often EVE publishes metrics during these tests. Lowered from the default
// minute so that a wait spans several samples; the metrics message itself is
// never faulted, since it does not travel the deferred queue.
const metricIntervalSecs = 20

// How long to wait for the deferred queue state to show up in a metrics
// message, covering the fault taking effect plus a couple of publications.
//
// The controller has to be new enough to parse these fields: it re-serializes
// what a device sent using its own copy of the API, and protojson drops what
// that copy does not carry, so against an older adam every counter here reads
// as unset however correctly the device reported it.
const metricsAppearTimeout = 4 * time.Minute

// How long the application has to hold its state after starting before a test
// stops it again. See waitUntilAppSettled.
const appSettleWindow = 45 * time.Second

// Path of the metrics endpoint, the one request in these tests which is never
// faulted, so its counters are what a delivered answer looks like.
const metricsPath = "/metrics"

// urlAnswerCounts sums, across every interface EVE reported, how the answers to
// the controller endpoint ending in suffix came out. One entry per interface
// the request went out on; which one carried it does not matter here.
func urlAnswerCounts(dm *evemetrics.DeviceMetric,
	suffix string) (delivered, retriable, rejected int64) {
	for _, zc := range dm.GetZedcloud() {
		for _, um := range zc.GetUrlMetrics() {
			if !strings.HasSuffix(um.GetUrl(), suffix) {
				continue
			}
			delivered += um.GetDeliveredMsgCount()
			retriable += um.GetRetriableErrCount()
			rejected += um.GetRejectedErrCount()
		}
	}
	return delivered, retriable, rejected
}

// latestDeviceMetric drains the watch channel and returns the last metrics
// message on it, waiting for one if the channel is empty. Counters are
// cumulative since boot, so a baseline has to be the most recent sample rather
// than whichever one happens to be queued.
func latestDeviceMetric(t *WithT,
	updates <-chan *evemetrics.DeviceMetric) *evemetrics.DeviceMetric {
	var latest *evemetrics.DeviceMetric
	for {
		select {
		case dm := <-updates:
			latest = dm
			continue
		default:
		}
		if latest != nil {
			return latest
		}
		t.Eventually(updates, metricsAppearTimeout).Should(Receive(&latest))
	}
}

// deferredMetricsDeviceConfig is appDeviceConfig with metrics published often
// enough for a test to watch the deferred queue change.
func deferredMetricsDeviceConfig() (*evetest.EdgeDeviceConfig, uuid.UUID) {
	devConfig, appUUID := appDeviceConfig()
	cfgProps := pillartypes.NewConfigItemValueMap()
	cfgProps.SetGlobalValueInt(pillartypes.MetricInterval, metricIntervalSecs)
	devConfig.SetConfigProperties(cfgProps)
	return devConfig, appUUID
}

// baselineDeviceMetric returns a metrics message published after this point,
// discarding whatever was already queued. The counters are cumulative, so a
// baseline taken from a sample predating the application starting would be
// compared against a different device state.
func baselineDeviceMetric(t *WithT,
	updates <-chan *evemetrics.DeviceMetric) *evemetrics.DeviceMetric {
	for drained := false; !drained; {
		select {
		case <-updates:
		default:
			drained = true
		}
	}
	var dm *evemetrics.DeviceMetric
	t.Eventually(updates, metricsAppearTimeout).Should(Receive(&dm))
	return dm
}

// waitUntilAppSettled requires the application to stay running for a while
// after it starts, before a test stops it again. A container stopped in the
// moment it comes up can take far longer to finish than one which was actually
// running, which then outlasts every wait a following subtest allows for it.
//
// Further reports arriving during the window are expected and not a problem --
// an address being assigned produces one without the state changing -- so this
// checks what they say rather than that they stop coming.
func waitUntilAppSettled(t *WithT, updates <-chan *eveinfo.ZInfoApp) {
	// The channel still holds the reports of the deployment which has just
	// finished, so what matters is the state left at the end of the window,
	// not the state of any one report in it.
	settled := time.After(appSettleWindow)
	state := eveinfo.ZSwState_RUNNING
	for {
		select {
		case update := <-updates:
			state = update.GetState()
		case <-settled:
			t.Expect(state).To(Equal(eveinfo.ZSwState_RUNNING),
				"application left RUNNING before the test stopped it")
			return
		}
	}
}

// settleApp waits until the controller has been told the application reached
// its terminal state, which is cleanup rather than assertion: the reset a
// following subtest performs allows deviceApplyConfigTimeout for the
// application to be reported gone, and that does not cover finishing a
// container shutdown as well as deleting it. A subtest which returns while its
// application is still stopping therefore fails the next one's setup, so each
// absorbs the shutdown it started.
func settleApp(t *WithT, updates <-chan *eveinfo.ZInfoApp) {
	t.Eventually(updates, convergeTimeout).Should(Receive(
		matchers.SatisfyPredicate("Application is reported HALTED",
			isAppState(eveinfo.ZSwState_HALTED)).StopIf(appHasError)))
}

// TestDeferredQueueBacklogReported verifies that while the controller is
// refusing info messages with a status EVE will offer them against again, the
// device says so: the metrics report a growing queue of undelivered messages,
// how long the oldest of them has been waiting, and the refusals counted
// against the info endpoint.
//
// Without this the only sign that reports are piling up is their absence, which
// is indistinguishable from a device with nothing to say. The counters are also
// what tells a controller having trouble apart from one turning the payload
// away - see TestDeferredQueueDropsReported for the other half.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- the fault is injected at the controller.
//
// Device configuration
// --------------------
//   - As in TestInfoRetriedAfterServerError, plus timer.metric.interval lowered
//     to metricIntervalSecs.
//
// Phases
// ------
//  1. Deploy the application and wait until it is reported RUNNING, then take
//     the metrics counters as a baseline.
//  2. Arm a fault answering every info request with 503 and deactivate the
//     application, so that reports are produced and refused.
//  3. A metrics message has to reach the controller reporting a non-empty
//     deferred queue with an oldest-message timestamp, and more refusals
//     against the info endpoint than the baseline. The metrics endpoint's delivered count must rise over
//     the same period, which is what shows the counters track answers rather
//     than merely counting requests.
//  4. Clear the fault. The queue has to drain back to empty on its own, with
//     nothing given up on along the way.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
func TestDeferredQueueBacklogReported(test *testing.T) {
	evetestT := evetest.Init(test)
	defer evetest.Close()
	if !evetest.ControllerFaultsEnabled() {
		test.Skip("controller fault injection is off; " +
			"set EVETEST_CONTROLLER_FAULTS=true to run this test")
	}
	t := NewGomegaWithT(evetestT)

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	hypervisor := evetest.GetHypervisorParameterValue()
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.SingleEthWithDHCP},
	)
	device := evetest.GetEdgeDevice(devName)
	log := evetest.Logger()
	evetest.Checkpoint("setup-done")

	// Phase 1: the application runs, metrics flow, and nothing is held back.
	devConfig, appUUID := deferredMetricsDeviceConfig()
	metricUpdates, stopMetricWatch := device.WatchDeviceMetrics()
	defer stopMetricWatch()
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	device.ApplyConfig(devConfig, true, true)
	device.WaitUntilAppIsRunning(appUUID, 5*time.Minute)
	waitUntilAppSettled(t, appUpdates)
	evetest.Checkpoint("app-running")

	baseline := baselineDeviceMetric(t, metricUpdates)
	t.Expect(baseline.GetDeferredQueue()).ToNot(BeNil(),
		"device does not report the deferred queue at all")
	_, baseInfoRetriable, _ := urlAnswerCounts(baseline, infoPath)
	baseMetricsDelivered, _, _ := urlAnswerCounts(baseline, metricsPath)
	baseDropped := baseline.GetDeferredQueue().GetDroppedMsgCount()
	log.Infof("Baseline: info retriable=%d, metrics delivered=%d, dropped=%d",
		baseInfoRetriable, baseMetricsDelivered, baseDropped)

	// Phase 2: every info message is refused with a status worth retrying.
	evetest.ArmControllerFault(evetest.ControllerFault{
		Method:     http.MethodPost,
		PathSuffix: infoPath,
		Action:     evetest.FaultAnswerStatus,
		StatusCode: http.StatusServiceUnavailable,
	})
	defer evetest.ClearControllerFaults()
	log.Info("Controller now answers 503 to every info message")
	device.DeactivateApplication(appUUID, false, 0)

	// Phase 3: the backlog and the refusals have to be visible in the metrics.
	t.Eventually(metricUpdates, metricsAppearTimeout).Should(Receive(
		matchers.SatisfyPredicate("Metrics report the held back messages",
			func(dm *evemetrics.DeviceMetric) bool {
				dq := dm.GetDeferredQueue()
				if dq.GetUndeliveredMsgCount() == 0 ||
					dq.GetOldestUndeliveredMsg() == nil {
					return false
				}
				_, retriable, _ := urlAnswerCounts(dm, infoPath)
				delivered, _, _ := urlAnswerCounts(dm, metricsPath)
				return retriable > baseInfoRetriable &&
					delivered > baseMetricsDelivered
			})))
	evetest.Checkpoint("backlog-reported")

	// Refusing a message is not giving up on it, so nothing may be counted
	// lost. The only report EVE puts on the queue which it *is* willing to
	// drop is the location, and that is published only when a modem supplies
	// one, so on this network model there is nothing else to account for.
	held := latestDeviceMetric(t, metricUpdates)
	t.Expect(held.GetDeferredQueue().GetDroppedMsgCount()).To(Equal(baseDropped),
		"a message was given up on despite a retriable answer")
	oldest := held.GetDeferredQueue().GetOldestUndeliveredMsg().AsTime()
	log.Infof("Oldest undelivered message has been waiting %v",
		time.Since(oldest).Round(time.Second))
	t.Expect(oldest).To(BeTemporally("<", time.Now()),
		"the oldest undelivered message is dated in the future")

	// Phase 4: with the controller accepting info again the queue empties out.
	evetest.ClearControllerFaults()
	log.Info("Controller accepts info messages again")
	t.Eventually(metricUpdates, convergeTimeout).Should(Receive(
		matchers.SatisfyPredicate("Deferred queue is reported empty again",
			func(dm *evemetrics.DeviceMetric) bool {
				return dm.GetDeferredQueue().GetUndeliveredMsgCount() == 0
			})))
	evetest.Checkpoint("backlog-drained")

	settleApp(t, appUpdates)
}

// TestDeferredQueueDropsReported verifies that a message the controller rejects
// outright, which EVE gives up on rather than offering again, is counted and
// reported: the drop shows up in the deferred queue metric as a rejection, with
// the time of the most recent one, and against the info endpoint as a rejected
// answer.
//
// This is the state the controller would otherwise never learn about - the
// device stops mentioning the object and there is nothing to notice. It is also
// what separates the two refusal classes: the same fault shape as
// TestDeferredQueueBacklogReported, with a status EVE does not retry, has to
// land in different counters.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP.
//
// Device configuration
// --------------------
//   - As in TestDeferredQueueBacklogReported.
//
// Phases
// ------
//  1. Deploy the application and wait until it is reported RUNNING, then take
//     the metrics counters as a baseline.
//  2. Arm a fault rejecting every info request with 404, the answer a controller
//     gives for an object it no longer knows about, and deactivate the
//     application so reports are produced and rejected.
//  3. A metrics message reaching the controller has to report the drops as
//     rejections, with the time of the last one, and rejected answers against
//     the info endpoint. None of them
//     may be counted as superseded, which is the other, unrelated reason for
//     giving up on a message.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
func TestDeferredQueueDropsReported(test *testing.T) {
	evetestT := evetest.Init(test)
	defer evetest.Close()
	if !evetest.ControllerFaultsEnabled() {
		test.Skip("controller fault injection is off; " +
			"set EVETEST_CONTROLLER_FAULTS=true to run this test")
	}
	t := NewGomegaWithT(evetestT)

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	hypervisor := evetest.GetHypervisorParameterValue()
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.SingleEthWithDHCP},
	)
	device := evetest.GetEdgeDevice(devName)
	log := evetest.Logger()
	evetest.Checkpoint("setup-done")

	devConfig, appUUID := deferredMetricsDeviceConfig()
	metricUpdates, stopMetricWatch := device.WatchDeviceMetrics()
	defer stopMetricWatch()
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	device.ApplyConfig(devConfig, true, true)
	device.WaitUntilAppIsRunning(appUUID, 5*time.Minute)
	waitUntilAppSettled(t, appUpdates)
	evetest.Checkpoint("app-running")

	baseline := baselineDeviceMetric(t, metricUpdates)
	t.Expect(baseline.GetDeferredQueue()).ToNot(BeNil(),
		"device does not report the deferred queue at all")
	baseRejectedMsgs := baseline.GetDeferredQueue().GetRejectedMsgCount()
	baseDropped := baseline.GetDeferredQueue().GetDroppedMsgCount()
	baseSuperseded := baseline.GetDeferredQueue().GetSupersededMsgCount()
	_, _, baseInfoRejected := urlAnswerCounts(baseline, infoPath)
	log.Infof("Baseline: dropped=%d rejected=%d superseded=%d, info rejected=%d",
		baseDropped, baseRejectedMsgs, baseSuperseded, baseInfoRejected)

	evetest.ArmControllerFault(evetest.ControllerFault{
		Method:     http.MethodPost,
		PathSuffix: infoPath,
		Action:     evetest.FaultAnswerStatus,
		StatusCode: http.StatusNotFound,
	})
	defer evetest.ClearControllerFaults()
	log.Info("Controller now rejects every info message with 404")
	device.DeactivateApplication(appUUID, false, 0)

	t.Eventually(metricUpdates, metricsAppearTimeout).Should(Receive(
		matchers.SatisfyPredicate("Metrics report the rejected messages",
			func(dm *evemetrics.DeviceMetric) bool {
				dq := dm.GetDeferredQueue()
				if dq.GetLastDroppedMsg() == nil {
					return false
				}
				_, _, rejected := urlAnswerCounts(dm, infoPath)
				return dq.GetRejectedMsgCount() > baseRejectedMsgs &&
					dq.GetDroppedMsgCount() > baseDropped &&
					rejected > baseInfoRejected
			})))
	evetest.Checkpoint("rejections-reported")

	// A rejection is not a supersession: the two reasons for giving up on a
	// message have to stay apart, since only one of them means state was lost.
	// Nothing here can supersede - see TestDeferredQueueBacklogReported - so
	// the superseded count has to be exactly where it started.
	dropped := latestDeviceMetric(t, metricUpdates)
	dq := dropped.GetDeferredQueue()
	t.Expect(dq.GetSupersededMsgCount()).To(Equal(baseSuperseded),
		"a rejected message was counted as superseded")
	t.Expect(dq.GetDroppedMsgCount()).To(BeNumerically(">=",
		dq.GetRejectedMsgCount()+dq.GetSupersededMsgCount()),
		"the drop total does not account for its own breakdown")
	log.Infof("Last message given up on at %v",
		dq.GetLastDroppedMsg().AsTime())

	// The rejections stop here, and the application is only beginning to stop,
	// so its terminal state is reported normally.
	evetest.ClearControllerFaults()
	settleApp(t, appUpdates)
}
