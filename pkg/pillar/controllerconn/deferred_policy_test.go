// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package controllerconn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/netdump"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

// fakeSender answers every send with a canned outcome, selected by the URL of
// the request, and records the URLs it was asked to send to.
type fakeSender struct {
	sync.Mutex
	outcomes map[string][]fakeOutcome
	sentURLs []string
}

type fakeOutcome struct {
	statusCode int
	status     types.SenderStatus
	err        error
}

func newFakeSender() *fakeSender {
	return &fakeSender{outcomes: make(map[string][]fakeOutcome)}
}

// respond queues the outcomes to return for the consecutive sends to url. The
// last one is repeated once the others have been used up.
func (f *fakeSender) respond(url string, outcomes ...fakeOutcome) {
	f.Lock()
	defer f.Unlock()
	f.outcomes[url] = outcomes
}

func (f *fakeSender) SendOnAllIntf(_ context.Context, url string, _ *bytes.Buffer,
	_ RequestOptions) (SendRetval, error) {
	f.Lock()
	defer f.Unlock()
	f.sentURLs = append(f.sentURLs, url)
	outcomes := f.outcomes[url]
	if len(outcomes) == 0 {
		return SendRetval{ReqURL: url}, nil
	}
	outcome := outcomes[0]
	if len(outcomes) > 1 {
		f.outcomes[url] = outcomes[1:]
	}
	rv := SendRetval{
		ReqURL:             url,
		Status:             outcome.status,
		LastHTTPStatusCode: outcome.statusCode,
	}
	err := outcome.err
	if err == nil && outcome.statusCode != 0 &&
		(outcome.statusCode < 200 || outcome.statusCode >= 300) {
		// SendOnIntf turns any non-2xx into an error as well.
		err = errors.New(http.StatusText(outcome.statusCode))
	}
	return rv, err
}

func (f *fakeSender) GetContextForAllIntfFunctions() (context.Context,
	context.CancelFunc) {
	return context.WithCancel(context.Background())
}

func (f *fakeSender) sends() []string {
	f.Lock()
	defer f.Unlock()
	return append([]string{}, f.sentURLs...)
}

// levelRecorder captures the severity of every log record a queue emits, so a
// test can assert that a condition is reported loudly rather than in passing.
type levelRecorder struct {
	sync.Mutex
	messages map[logrus.Level][]string
}

func newLevelRecorder() *levelRecorder {
	return &levelRecorder{messages: make(map[logrus.Level][]string)}
}

func (r *levelRecorder) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (r *levelRecorder) Fire(entry *logrus.Entry) error {
	r.Lock()
	defer r.Unlock()
	r.messages[entry.Level] = append(r.messages[entry.Level], entry.Message)
	return nil
}

func (r *levelRecorder) at(level logrus.Level) []string {
	r.Lock()
	defer r.Unlock()
	return append([]string{}, r.messages[level]...)
}

// newTestQueueWithLog returns a queue whose log records are captured.
// The log source has to be unique per test: NewSourceLogObject keeps a global
// map keyed by source name and hands back the object already registered under
// that name, which would leave the records going to another test's logger.
func newTestQueueWithLog(test *testing.T,
	sender deferredSender) (*DeferredQueue, *levelRecorder) {
	recorder := newLevelRecorder()
	logger := logrus.New()
	logger.SetLevel(logrus.TraceLevel)
	logger.SetOutput(io.Discard)
	logger.AddHook(recorder)
	queue := newTestQueue(sender, nil)
	queue.log = base.NewSourceLogObject(logger, test.Name(), 1234)
	return queue, recorder
}

// newTestQueue returns a queue with no background processing task, so that a
// test drives the passes itself by calling handleDeferred.
func newTestQueue(sender deferredSender,
	sentHandler SentHandlerFunction) *DeferredQueue {
	logger := logrus.StandardLogger()
	return &DeferredQueue{
		log:               base.NewSourceLogObject(logger, "deferred-test", 1234),
		deferredItemsLock: &sync.Mutex{},
		Ticker:            flextimer.NewRangeTicker(longTime1, longTime2),
		sentHandler:       sentHandler,
		priorityCheckFunctions: []TypePriorityCheckFunction{
			func(interface{}) bool { return true },
		},
		ctrlClient: sender,
	}
}

// reportedStatuses collects the outcomes handed to the sentHandler callback,
// leaving out the SenderStatusDebug notifications for items left in the queue.
type reportedStatuses struct {
	sync.Mutex
	statuses []types.SenderStatus
}

func (r *reportedStatuses) handler() SentHandlerFunction {
	return func(_ interface{}, _ *bytes.Buffer, result types.SenderStatus,
		_ []netdump.TracedNetRequest) {
		if result == types.SenderStatusDebug {
			return
		}
		r.Lock()
		defer r.Unlock()
		r.statuses = append(r.statuses, result)
	}
}

func (r *reportedStatuses) get() []types.SenderStatus {
	r.Lock()
	defer r.Unlock()
	return append([]types.SenderStatus{}, r.statuses...)
}

func (q *DeferredQueue) queuedKeys() []string {
	q.deferredItemsLock.Lock()
	defer q.deferredItemsLock.Unlock()
	var keys []string
	for _, item := range q.deferredItems {
		keys = append(keys, item.key)
	}
	return keys
}

func (q *DeferredQueue) queuedItem(key string) *deferredItem {
	q.deferredItemsLock.Lock()
	defer q.deferredItemsLock.Unlock()
	for _, item := range q.deferredItems {
		if item.key == key {
			return item
		}
	}
	return nil
}

func (q *DeferredQueue) queuedItems() []*deferredItem {
	q.deferredItemsLock.Lock()
	defer q.deferredItemsLock.Unlock()
	return append([]*deferredItem{}, q.deferredItems...)
}

const testURL = "https://controller.example.com/api/v2/edgedevice/id/dev/info"

func TestDeferredRetriesTemporaryRejection(test *testing.T) {
	t := NewGomegaWithT(test)
	sender := newFakeSender()
	sender.respond(testURL, fakeOutcome{
		statusCode: http.StatusServiceUnavailable,
		status:     types.SenderStatusUpgrade,
	})
	reported := &reportedStatuses{}
	queue := newTestQueue(sender, reported.handler())

	queue.SetDeferred("appInfo", bytes.NewBufferString("app is running"),
		testURL, nil, DeferredItemOpts{BailOnHTTPErr: true})

	t.Expect(queue.handleDeferred()).To(BeFalse())
	t.Expect(queue.queuedKeys()).To(Equal([]string{"appInfo"}))
	item := queue.queuedItem("appInfo")
	t.Expect(item.attempts).To(Equal(1))
	t.Expect(item.retryAt).To(BeTemporally(">", time.Now()))
	t.Expect(reported.get()).To(Equal([]types.SenderStatus{types.SenderStatusUpgrade}))

	// A second pass before the backoff has elapsed must not touch the controller.
	t.Expect(queue.handleDeferred()).To(BeFalse())
	t.Expect(sender.sends()).To(HaveLen(1))

	// Once it has elapsed, the very same payload is offered again and accepted.
	sender.respond(testURL, fakeOutcome{statusCode: http.StatusOK})
	queue.queuedItem("appInfo").retryAt = time.Now().Add(-time.Second)
	t.Expect(queue.handleDeferred()).To(BeTrue())
	t.Expect(sender.sends()).To(HaveLen(2))
	t.Expect(queue.queuedKeys()).To(BeEmpty())
}

func TestDeferredDropsPermanentRejection(test *testing.T) {
	t := NewGomegaWithT(test)
	sender := newFakeSender()
	sender.respond(testURL, fakeOutcome{
		statusCode: http.StatusBadRequest,
		status:     types.SenderStatusNotFound,
	})
	reported := &reportedStatuses{}
	queue := newTestQueue(sender, reported.handler())

	queue.SetDeferred("appInfo", bytes.NewBufferString("app is running"),
		testURL, nil, DeferredItemOpts{BailOnHTTPErr: true})

	t.Expect(queue.handleDeferred()).To(BeTrue())
	t.Expect(queue.queuedKeys()).To(BeEmpty())
	t.Expect(reported.get()).To(Equal([]types.SenderStatus{types.SenderStatusNotFound}))
	t.Expect(sender.sends()).To(HaveLen(1))
}

// A rejected item must not keep the items behind it from being delivered, and
// must not be the first one tried on the next pass either.
func TestDeferredRejectedItemDoesNotBlockOthers(test *testing.T) {
	t := NewGomegaWithT(test)
	const otherURL = "https://controller.example.com/api/v2/edgedevice/id/dev/other"
	sender := newFakeSender()
	sender.respond(testURL, fakeOutcome{statusCode: http.StatusInternalServerError})
	sender.respond(otherURL, fakeOutcome{statusCode: http.StatusOK})
	queue := newTestQueue(sender, nil)

	// Queued the way NTP sources and patch envelope status are: errors are not
	// ignored and other ports are tried on an HTTP error.
	queue.SetDeferred("refused", bytes.NewBufferString("refused payload"),
		testURL, nil, DeferredItemOpts{})
	queue.SetDeferred("accepted", bytes.NewBufferString("accepted payload"),
		otherURL, nil, DeferredItemOpts{})

	t.Expect(queue.handleDeferred()).To(BeFalse())
	t.Expect(sender.sends()).To(Equal([]string{testURL, otherURL}))
	t.Expect(queue.queuedKeys()).To(Equal([]string{"refused"}))

	// The item waiting out its backoff goes to the tail of the queue.
	queue.SetDeferred("fresh", bytes.NewBufferString("fresh payload"),
		otherURL, nil, DeferredItemOpts{})
	t.Expect(queue.queuedKeys()).To(Equal([]string{"refused", "fresh"}))
	t.Expect(queue.handleDeferred()).To(BeFalse())
	t.Expect(queue.queuedKeys()).To(Equal([]string{"refused"}))
}

// Losing the controller entirely is not a reason to give up on a message, and
// it stops the pass because the remaining items would fail the same way.
func TestDeferredKeepsItemWhenControllerUnreachable(test *testing.T) {
	t := NewGomegaWithT(test)
	const otherURL = "https://controller.example.com/api/v2/edgedevice/id/dev/other"
	sender := newFakeSender()
	sender.respond(testURL, fakeOutcome{err: errors.New("no route to host")})
	sender.respond(otherURL, fakeOutcome{statusCode: http.StatusOK})
	reported := &reportedStatuses{}
	queue := newTestQueue(sender, reported.handler())

	queue.SetDeferred("unreachable", bytes.NewBufferString("payload"),
		testURL, nil, DeferredItemOpts{BailOnHTTPErr: true})
	queue.SetDeferred("behind", bytes.NewBufferString("payload"),
		otherURL, nil, DeferredItemOpts{BailOnHTTPErr: true})

	t.Expect(queue.handleDeferred()).To(BeFalse())
	t.Expect(sender.sends()).To(Equal([]string{testURL}))
	t.Expect(queue.queuedKeys()).To(Equal([]string{"unreachable", "behind"}))
	item := queue.queuedItem("unreachable")
	t.Expect(item.attempts).To(BeZero())
	t.Expect(item.retryAt).To(BeZero())
	t.Expect(reported.get()).To(Equal([]types.SenderStatus{types.SenderStatusFailed}))
}

// A payload which the next period supersedes is discarded rather than retried.
func TestDeferredDiscardsSupersededPayload(test *testing.T) {
	t := NewGomegaWithT(test)
	sender := newFakeSender()
	sender.respond(testURL, fakeOutcome{statusCode: http.StatusServiceUnavailable})
	queue := newTestQueue(sender, nil)

	queue.SetDeferred("metrics", bytes.NewBufferString("metrics"), testURL, nil,
		DeferredItemOpts{DiscardOnFailure: true})

	t.Expect(queue.handleDeferred()).To(BeTrue())
	t.Expect(queue.queuedKeys()).To(BeEmpty())
}

// A message nothing else re-asserts is never given up on while the controller
// keeps answering with a temporary error, however long that lasts. The delay
// between attempts grows to its ceiling and stays there.
func TestDeferredNeverGivesUpOnTemporaryRejection(test *testing.T) {
	t := NewGomegaWithT(test)
	sender := newFakeSender()
	sender.respond(testURL, fakeOutcome{statusCode: http.StatusBadGateway})
	queue := newTestQueue(sender, nil)

	queue.SetDeferred("appInfo", bytes.NewBufferString("app is running"),
		testURL, nil, DeferredItemOpts{BailOnHTTPErr: true})

	const attempts = 50
	for i := 1; i <= attempts; i++ {
		t.Expect(queue.handleDeferred()).To(BeFalse())
		item := queue.queuedItem("appInfo")
		t.Expect(item).ToNot(BeNil())
		t.Expect(item.attempts).To(Equal(i))
		t.Expect(item.retryAt).To(BeTemporally(">", time.Now()))
		// Let the backoff elapse so that the next pass attempts the item again.
		item.retryAt = time.Now().Add(-time.Second)
	}
	t.Expect(sender.sends()).To(HaveLen(attempts))
	t.Expect(queue.queuedKeys()).To(Equal([]string{"appInfo"}))

	// It is still the same payload, and it is delivered once accepted.
	sender.respond(testURL, fakeOutcome{statusCode: http.StatusOK})
	t.Expect(queue.handleDeferred()).To(BeTrue())
	t.Expect(queue.queuedKeys()).To(BeEmpty())
}

// The queue holds at most one item per key, so keeping messages instead of
// discarding them cannot grow it beyond the number of objects being reported.
func TestDeferredQueueLengthBoundedByKeys(test *testing.T) {
	t := NewGomegaWithT(test)
	sender := newFakeSender()
	sender.respond(testURL, fakeOutcome{statusCode: http.StatusServiceUnavailable})
	queue := newTestQueue(sender, nil)

	const keys = 5
	const rounds = 10
	for round := 0; round < rounds; round++ {
		for k := 0; k < keys; k++ {
			queue.SetDeferred(fmt.Sprintf("appInfo%d", k),
				bytes.NewBufferString(fmt.Sprintf("state %d", round)),
				testURL, nil, DeferredItemOpts{BailOnHTTPErr: true})
		}
		queue.handleDeferred()
		for _, item := range queue.queuedItems() {
			item.retryAt = time.Now().Add(-time.Second)
		}
	}

	t.Expect(queue.queuedKeys()).To(HaveLen(keys))
	// Only the newest payload per key is retained.
	for _, item := range queue.queuedItems() {
		t.Expect(item.buf.String()).To(Equal(fmt.Sprintf("state %d", rounds-1)))
	}
}

// Replacing the payload of a queued item makes it eligible again, since the
// controller has not seen the new bytes yet.
func TestDeferredResetsBackoffOnNewPayload(test *testing.T) {
	t := NewGomegaWithT(test)
	sender := newFakeSender()
	sender.respond(testURL, fakeOutcome{statusCode: http.StatusServiceUnavailable},
		fakeOutcome{statusCode: http.StatusOK})
	queue := newTestQueue(sender, nil)

	queue.SetDeferred("appInfo", bytes.NewBufferString("app is booting"),
		testURL, nil, DeferredItemOpts{BailOnHTTPErr: true})
	t.Expect(queue.handleDeferred()).To(BeFalse())
	t.Expect(queue.queuedItem("appInfo").attempts).To(Equal(1))

	queue.SetDeferred("appInfo", bytes.NewBufferString("app is running"),
		testURL, nil, DeferredItemOpts{BailOnHTTPErr: true})
	item := queue.queuedItem("appInfo")
	t.Expect(item.attempts).To(BeZero())
	t.Expect(item.retryAt).To(BeZero())
	t.Expect(queue.handleDeferred()).To(BeTrue())
}

// itemKind stands in for the info/attest types zedagent uses to assign priority.
type itemKind string

// newPriorityTestQueue builds a queue with the same shape of priority functions
// as zedagent installs: attest first, then app info, then everything else.
func newPriorityTestQueue(sender deferredSender) *DeferredQueue {
	queue := newTestQueue(sender, nil)
	isKind := func(want itemKind) TypePriorityCheckFunction {
		return func(itemType interface{}) bool {
			kind, ok := itemType.(itemKind)
			return ok && kind == want
		}
	}
	queue.priorityCheckFunctions = []TypePriorityCheckFunction{
		isKind("attest"), isKind("app"),
		func(interface{}) bool { return true },
	}
	return queue
}

// A refused item must not stop the classes behind it from being sent in the same
// pass. Before, one failure broke out of both the item loop and the loop over
// priority classes, so everything of lower priority waited for the next pass.
func TestDeferredRefusedItemDoesNotBlockLowerPriorityClasses(test *testing.T) {
	t := NewGomegaWithT(test)
	const attestURL = "https://controller.example.com/api/v2/edgedevice/id/dev/attest"
	const otherURL = "https://controller.example.com/api/v2/edgedevice/id/dev/other"
	sender := newFakeSender()
	sender.respond(attestURL, fakeOutcome{statusCode: http.StatusServiceUnavailable})
	sender.respond(testURL, fakeOutcome{statusCode: http.StatusOK})
	sender.respond(otherURL, fakeOutcome{statusCode: http.StatusOK})
	queue := newPriorityTestQueue(sender)

	// Enqueued in reverse priority order to prove the order of sending comes
	// from the priority functions and not from the order of arrival.
	queue.SetDeferred("volumeInfo", bytes.NewBufferString("volume"), otherURL,
		itemKind("volume"), DeferredItemOpts{BailOnHTTPErr: true})
	queue.SetDeferred("appInfo", bytes.NewBufferString("app"), testURL,
		itemKind("app"), DeferredItemOpts{BailOnHTTPErr: true})
	queue.SetDeferred("attest", bytes.NewBufferString("attest"), attestURL,
		itemKind("attest"), DeferredItemOpts{BailOnHTTPErr: true})

	t.Expect(queue.handleDeferred()).To(BeFalse())
	// The refused highest-priority item did not stop the two behind it.
	t.Expect(sender.sends()).To(Equal([]string{attestURL, testURL, otherURL}))
	t.Expect(queue.queuedKeys()).To(Equal([]string{"attest"}))
}

// Priority decides the order of sending; the demotion of a refused item applies
// within the queue and must not let a lower-priority item overtake a
// higher-priority one that is ready to be sent.
func TestDeferredPriorityOrderSurvivesDemotion(test *testing.T) {
	t := NewGomegaWithT(test)
	const otherURL = "https://controller.example.com/api/v2/edgedevice/id/dev/other"
	sender := newFakeSender()
	// App info is refused once, then accepted; the volume info always fails to
	// reach the controller, so it stays queued as well.
	sender.respond(testURL, fakeOutcome{statusCode: http.StatusServiceUnavailable},
		fakeOutcome{statusCode: http.StatusOK})
	sender.respond(otherURL, fakeOutcome{statusCode: http.StatusServiceUnavailable})
	queue := newPriorityTestQueue(sender)

	queue.SetDeferred("appInfo", bytes.NewBufferString("app"), testURL,
		itemKind("app"), DeferredItemOpts{BailOnHTTPErr: true})
	queue.SetDeferred("volumeInfo", bytes.NewBufferString("volume"), otherURL,
		itemKind("volume"), DeferredItemOpts{BailOnHTTPErr: true})

	t.Expect(queue.handleDeferred()).To(BeFalse())
	t.Expect(sender.sends()).To(Equal([]string{testURL, otherURL}))
	t.Expect(queue.queuedKeys()).To(ConsistOf("appInfo", "volumeInfo"))

	// Once both backoffs elapse, app info is still offered before volume info.
	for _, item := range queue.queuedItems() {
		item.retryAt = time.Now().Add(-time.Second)
	}
	t.Expect(queue.handleDeferred()).To(BeFalse())
	t.Expect(sender.sends()).To(Equal([]string{
		testURL, otherURL, testURL, otherURL}))
	t.Expect(queue.queuedKeys()).To(Equal([]string{"volumeInfo"}))
}

// Losing the controller entirely still abandons the pass, including the classes
// behind the item that could not be delivered - there is nothing to be gained
// from trying them over the same dead link.
func TestDeferredUnreachableControllerStopsLowerPriorityClasses(test *testing.T) {
	t := NewGomegaWithT(test)
	const otherURL = "https://controller.example.com/api/v2/edgedevice/id/dev/other"
	sender := newFakeSender()
	sender.respond(testURL, fakeOutcome{err: errors.New("no route to host")})
	sender.respond(otherURL, fakeOutcome{statusCode: http.StatusOK})
	queue := newPriorityTestQueue(sender)

	queue.SetDeferred("appInfo", bytes.NewBufferString("app"), testURL,
		itemKind("app"), DeferredItemOpts{BailOnHTTPErr: true})
	queue.SetDeferred("volumeInfo", bytes.NewBufferString("volume"), otherURL,
		itemKind("volume"), DeferredItemOpts{BailOnHTTPErr: true})

	t.Expect(queue.handleDeferred()).To(BeFalse())
	t.Expect(sender.sends()).To(Equal([]string{testURL}))
	t.Expect(queue.queuedKeys()).To(Equal([]string{"appInfo", "volumeInfo"}))
}

// Items arriving while a pass is running must not corrupt the queue or the retry
// state of the items being sent. Run with -race to make this meaningful.
func TestDeferredConcurrentSetDeferred(test *testing.T) {
	t := NewGomegaWithT(test)
	sender := newFakeSender()
	sender.respond(testURL, fakeOutcome{statusCode: http.StatusServiceUnavailable})
	queue := newTestQueue(sender, nil)

	queue.SetDeferred("appInfo", bytes.NewBufferString("app"), testURL, nil,
		DeferredItemOpts{BailOnHTTPErr: true})

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				queue.SetDeferred(fmt.Sprintf("key%d", n),
					bytes.NewBufferString("payload"), testURL, nil,
					DeferredItemOpts{BailOnHTTPErr: true})
			}
		}(i)
	}
	for i := 0; i < 25; i++ {
		queue.handleDeferred()
	}
	wg.Wait()

	// Every key that was set is either still queued or was accepted; nothing
	// may be lost or duplicated.
	t.Expect(queue.queuedKeys()).To(ContainElement("appInfo"))
	seen := make(map[string]int)
	for _, key := range queue.queuedKeys() {
		seen[key]++
	}
	for key, count := range seen {
		t.Expect(count).To(Equal(1), "key %s queued %d times", key, count)
	}
}

// A payload the controller keeps refusing has to be called out, since it is
// never given up on and nothing else reports that the state is not getting
// through.
func TestDeferredWarnsAboutRepeatedlyRefusedMessage(test *testing.T) {
	t := NewGomegaWithT(test)
	sender := newFakeSender()
	sender.respond(testURL, fakeOutcome{statusCode: http.StatusServiceUnavailable})
	queue, recorder := newTestQueueWithLog(test, sender)

	queue.SetDeferred("appInfo", bytes.NewBufferString("app is running"),
		testURL, nil, DeferredItemOpts{BailOnHTTPErr: true})

	for i := 1; i < warnAfterAttempts; i++ {
		queue.handleDeferred()
		queue.queuedItem("appInfo").retryAt = time.Now().Add(-time.Second)
	}
	// Up to the threshold the retries are reported without raising the alarm.
	t.Expect(recorder.at(logrus.WarnLevel)).To(BeEmpty())
	t.Expect(recorder.at(logrus.InfoLevel)).To(HaveLen(warnAfterAttempts - 1))

	queue.handleDeferred()
	warnings := recorder.at(logrus.WarnLevel)
	t.Expect(warnings).To(HaveLen(1))
	t.Expect(warnings[0]).To(ContainSubstring("attempt 20"))
	// The message is still queued: being loud about it is not giving up on it.
	t.Expect(queue.queuedKeys()).To(Equal([]string{"appInfo"}))
}

// Reporting an object again without its reported state having changed must not
// restart the delay nor reset how many times the message has been refused,
// otherwise a busy device would both hammer the controller and never reach the
// threshold that makes a stuck message visible.
func TestDeferredUnchangedRepublishKeepsRetryState(test *testing.T) {
	t := NewGomegaWithT(test)
	sender := newFakeSender()
	sender.respond(testURL, fakeOutcome{statusCode: http.StatusServiceUnavailable})
	queue := newTestQueue(sender, nil)

	const payload = "app is running"
	queue.SetDeferred("appInfo", bytes.NewBufferString(payload), testURL, nil,
		DeferredItemOpts{BailOnHTTPErr: true})
	t.Expect(queue.handleDeferred()).To(BeFalse())
	item := queue.queuedItem("appInfo")
	t.Expect(item.attempts).To(Equal(1))
	retryAt := item.retryAt

	// Same bytes: the queued message is unchanged, so its retry state stands.
	queue.SetDeferred("appInfo", bytes.NewBufferString(payload), testURL, nil,
		DeferredItemOpts{BailOnHTTPErr: true})
	item = queue.queuedItem("appInfo")
	t.Expect(item.attempts).To(Equal(1))
	t.Expect(item.retryAt).To(Equal(retryAt))
	// And it is not attempted again while the delay stands.
	t.Expect(queue.handleDeferred()).To(BeFalse())
	t.Expect(sender.sends()).To(HaveLen(1))

	// Different bytes: a new message, which deserves an immediate attempt.
	queue.SetDeferred("appInfo", bytes.NewBufferString("app is halting"),
		testURL, nil, DeferredItemOpts{BailOnHTTPErr: true})
	item = queue.queuedItem("appInfo")
	t.Expect(item.attempts).To(BeZero())
	t.Expect(item.retryAt).To(BeZero())
	t.Expect(queue.handleDeferred()).To(BeFalse())
	t.Expect(sender.sends()).To(HaveLen(2))
}

// A long backlog of undelivered messages is called out once per pass.
func TestDeferredWarnsAboutBacklog(test *testing.T) {
	t := NewGomegaWithT(test)
	sender := newFakeSender()
	sender.respond(testURL, fakeOutcome{statusCode: http.StatusServiceUnavailable})
	queue, recorder := newTestQueueWithLog(test, sender)

	for i := 0; i <= queueBacklogWarn; i++ {
		queue.SetDeferred(fmt.Sprintf("appInfo%d", i),
			bytes.NewBufferString("state"), testURL, nil,
			DeferredItemOpts{BailOnHTTPErr: true})
	}
	queue.handleDeferred()

	var backlogWarnings []string
	for _, msg := range recorder.at(logrus.WarnLevel) {
		if strings.Contains(msg, "the rest to be sent") {
			backlogWarnings = append(backlogWarnings, msg)
		}
	}
	t.Expect(backlogWarnings).To(HaveLen(1))
	t.Expect(backlogWarnings[0]).To(ContainSubstring(
		fmt.Sprintf("%d", queueBacklogWarn+1)))
}

// An airgapped device is not expected to reach a controller, so its backlog is
// not an anomaly worth warning about.
func TestDeferredBacklogQuietWhenLogsSuppressed(test *testing.T) {
	t := NewGomegaWithT(test)
	sender := newFakeSender()
	sender.respond(testURL, fakeOutcome{statusCode: http.StatusServiceUnavailable})
	queue, recorder := newTestQueueWithLog(test, sender)

	for i := 0; i <= queueBacklogWarn; i++ {
		queue.SetDeferred(fmt.Sprintf("appInfo%d", i),
			bytes.NewBufferString("state"), testURL, nil,
			DeferredItemOpts{BailOnHTTPErr: true, SuppressLogs: true})
	}
	queue.handleDeferred()

	for _, msg := range recorder.at(logrus.WarnLevel) {
		t.Expect(msg).ToNot(ContainSubstring("the rest to be sent"))
	}
	t.Expect(recorder.at(logrus.ErrorLevel)).To(BeEmpty())
}

func TestRetriableHTTPStatus(test *testing.T) {
	t := NewGomegaWithT(test)
	for _, code := range []int{
		http.StatusBadRequest, http.StatusNotFound, http.StatusMethodNotAllowed,
		http.StatusConflict, http.StatusGone, http.StatusRequestEntityTooLarge,
		http.StatusUnsupportedMediaType, http.StatusUnprocessableEntity,
	} {
		t.Expect(retriableHTTPStatus(code)).To(BeFalse(),
			"%d %s should not be retried", code, http.StatusText(code))
	}
	for _, code := range []int{
		// EVE renews what the controller refused and expects the same payload
		// to be accepted afterwards.
		http.StatusUnauthorized, http.StatusForbidden,
		http.StatusProxyAuthRequired,
		http.StatusRequestTimeout, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusNotImplemented,
		http.StatusBadGateway, http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	} {
		t.Expect(retriableHTTPStatus(code)).To(BeTrue(),
			"%d %s should be retried", code, http.StatusText(code))
	}
}

func TestRetryDelayGrowsToItsCeiling(test *testing.T) {
	t := NewGomegaWithT(test)
	t.Expect(retryDelay(1)).To(Equal(minRetryDelay))
	t.Expect(retryDelay(2)).To(Equal(2 * minRetryDelay))
	t.Expect(retryDelay(3)).To(Equal(4 * minRetryDelay))
	t.Expect(retryDelay(1000)).To(Equal(maxRetryDelay))
}
