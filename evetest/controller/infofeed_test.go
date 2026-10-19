// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeAdam serves one device's info endpoint the way Adam does: a plain GET
// returns every stored message, a streaming GET returns only messages
// received after it was opened.
type fakeAdam struct {
	t   *testing.T
	srv *httptest.Server

	mu      sync.Mutex
	stored  [][]byte
	streams map[chan []byte]struct{}
	// onStreamOpen, if set, runs once a stream is registered and before its
	// response headers are sent, i.e. before the client reads history.
	onStreamOpen func()
}

func newFakeAdam(t *testing.T, devUUID uuid.UUID) *fakeAdam {
	fa := &fakeAdam{t: t, streams: make(map[chan []byte]struct{})}
	path := "/admin/device/" + devUUID.String() + "/info"
	fa.srv = httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path {
				http.NotFound(w, r)
				return
			}
			if r.Header.Get(streamHeader) != streamValue {
				fa.mu.Lock()
				stored := append([][]byte(nil), fa.stored...)
				fa.mu.Unlock()
				for _, b := range stored {
					_, _ = w.Write(append(b, '\n'))
				}
				return
			}
			ch := make(chan []byte, 100)
			fa.mu.Lock()
			fa.streams[ch] = struct{}{}
			hook := fa.onStreamOpen
			fa.onStreamOpen = nil
			fa.mu.Unlock()
			if hook != nil {
				hook()
			}
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			for {
				select {
				case b, ok := <-ch:
					if !ok {
						return
					}
					_, _ = w.Write(append(b, '\n'))
					w.(http.Flusher).Flush()
				case <-r.Context().Done():
					fa.mu.Lock()
					delete(fa.streams, ch)
					fa.mu.Unlock()
					return
				}
			}
		}))
	t.Cleanup(fa.srv.Close)
	return fa
}

// receive stores msg and forwards it to every open stream.
func (fa *fakeAdam) receive(msg *eveinfo.ZInfoMsg) {
	b, err := protojson.Marshal(msg)
	if err != nil {
		fa.t.Fatal(err)
	}
	fa.mu.Lock()
	defer fa.mu.Unlock()
	fa.stored = append(fa.stored, b)
	for ch := range fa.streams {
		ch <- b
	}
}

// dropStreams ends every open stream, as an Adam restart would.
func (fa *fakeAdam) dropStreams() {
	fa.mu.Lock()
	defer fa.mu.Unlock()
	for ch := range fa.streams {
		close(ch)
		delete(fa.streams, ch)
	}
}

func newTestAdamClient(t *testing.T, fa *fakeAdam, devUUID uuid.UUID) *AdamClient {
	u, err := url.Parse(fa.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	// httptest's certificate names example.com and the loopback addresses.
	ac := NewAdamClient(logrus.NewEntry(log), t.TempDir(), "example.com",
		[]net.IP{net.ParseIP(host)}, uint16(port), fa.srv.Certificate(), nil, nil)
	ac.knownDevices[devUUID] = struct{}{}
	return ac
}

var testTime = time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)

func devMsg(sec int, restartCounter uint32) *eveinfo.ZInfoMsg {
	return &eveinfo.ZInfoMsg{
		Ztype:       eveinfo.ZInfoTypes_ZiDevice,
		AtTimeStamp: timestamppb.New(testTime.Add(time.Duration(sec) * time.Second)),
		InfoContent: &eveinfo.ZInfoMsg_Dinfo{Dinfo: &eveinfo.ZInfoDevice{
			RestartCounter: restartCounter,
		}},
	}
}

func appMsg(sec int, appID string, state eveinfo.ZSwState) *eveinfo.ZInfoMsg {
	return &eveinfo.ZInfoMsg{
		Ztype:       eveinfo.ZInfoTypes_ZiApp,
		AtTimeStamp: timestamppb.New(testTime.Add(time.Duration(sec) * time.Second)),
		InfoContent: &eveinfo.ZInfoMsg_Ainfo{Ainfo: &eveinfo.ZInfoApp{
			AppID: appID,
			State: state,
		}},
	}
}

func expectMsg(t *testing.T, ch <-chan *eveinfo.ZInfoMsg, want *eveinfo.ZInfoMsg) {
	t.Helper()
	select {
	case got, ok := <-ch:
		if !ok {
			t.Fatal("subscription channel closed")
		}
		if !proto.Equal(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %v", want)
	}
}

func expectNoMsg(t *testing.T, ch <-chan *eveinfo.ZInfoMsg) {
	t.Helper()
	select {
	case got := <-ch:
		t.Fatalf("unexpected message %v", got)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestSubscribeWithLatestReplaysLatestPerObject(t *testing.T) {
	devUUID := uuid.Must(uuid.NewV4())
	fa := newFakeAdam(t, devUUID)
	ac := newTestAdamClient(t, fa, devUUID)

	fa.receive(devMsg(1, 0))
	fa.receive(appMsg(2, "a", eveinfo.ZSwState_INSTALLED))
	fa.receive(devMsg(3, 0))
	fa.receive(appMsg(4, "b", eveinfo.ZSwState_RUNNING))
	fa.receive(appMsg(5, "a", eveinfo.ZSwState_RUNNING))
	// EVE reports a deleted object as its identifier alone.
	fa.receive(appMsg(6, "b", eveinfo.ZSwState_INVALID))

	ch := make(chan *eveinfo.ZInfoMsg, 16)
	unsub, err := ac.SubscribeToDeviceInfoMsgsWithLatest(devUUID, nil, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer unsub()

	expectMsg(t, ch, devMsg(3, 0))
	expectMsg(t, ch, appMsg(5, "a", eveinfo.ZSwState_RUNNING))
	expectMsg(t, ch, appMsg(6, "b", eveinfo.ZSwState_INVALID))
	expectNoMsg(t, ch)

	fa.receive(devMsg(7, 1))
	expectMsg(t, ch, devMsg(7, 1))
}

func TestSubscribeWithLatestAppliesMatch(t *testing.T) {
	devUUID := uuid.Must(uuid.NewV4())
	fa := newFakeAdam(t, devUUID)
	ac := newTestAdamClient(t, fa, devUUID)

	fa.receive(devMsg(1, 0))
	fa.receive(appMsg(2, "a", eveinfo.ZSwState_RUNNING))

	ch := make(chan *eveinfo.ZInfoMsg, 16)
	unsub, err := ac.SubscribeToDeviceInfoMsgsWithLatest(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiDevice
		}, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer unsub()

	expectMsg(t, ch, devMsg(1, 0))
	fa.receive(appMsg(3, "a", eveinfo.ZSwState_HALTED))
	fa.receive(devMsg(4, 1))
	expectMsg(t, ch, devMsg(4, 1))
}

func TestSubscribeWithLatestReplaysToEverySubscriber(t *testing.T) {
	devUUID := uuid.Must(uuid.NewV4())
	fa := newFakeAdam(t, devUUID)
	ac := newTestAdamClient(t, fa, devUUID)

	fa.receive(devMsg(1, 0))
	fa.receive(appMsg(2, "a", eveinfo.ZSwState_RUNNING))

	subscribe := func() chan *eveinfo.ZInfoMsg {
		ch := make(chan *eveinfo.ZInfoMsg, 16)
		unsub, err := ac.SubscribeToDeviceInfoMsgsWithLatest(devUUID, nil, ch)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(unsub)
		return ch
	}

	// Each later subscriber shares the first one's feed, so its replay
	// comes from the same saved state.
	ch1 := subscribe()
	expectMsg(t, ch1, devMsg(1, 0))
	expectMsg(t, ch1, appMsg(2, "a", eveinfo.ZSwState_RUNNING))
	ch2 := subscribe()
	expectMsg(t, ch2, devMsg(1, 0))
	expectMsg(t, ch2, appMsg(2, "a", eveinfo.ZSwState_RUNNING))

	fa.receive(devMsg(3, 1))
	expectMsg(t, ch1, devMsg(3, 1))
	expectMsg(t, ch2, devMsg(3, 1))
	ch3 := subscribe()
	expectMsg(t, ch3, appMsg(2, "a", eveinfo.ZSwState_RUNNING))
	expectMsg(t, ch3, devMsg(3, 1))
	expectNoMsg(t, ch3)
}

func TestSubscribeWithLatestEmptyStore(t *testing.T) {
	devUUID := uuid.Must(uuid.NewV4())
	fa := newFakeAdam(t, devUUID)
	ac := newTestAdamClient(t, fa, devUUID)

	ch := make(chan *eveinfo.ZInfoMsg, 16)
	unsub, err := ac.SubscribeToDeviceInfoMsgsWithLatest(devUUID, nil, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer unsub()

	expectNoMsg(t, ch)
	fa.receive(devMsg(1, 0))
	expectMsg(t, ch, devMsg(1, 0))
}

func TestSubscribeDeliversOnlyLiveMessages(t *testing.T) {
	devUUID := uuid.Must(uuid.NewV4())
	fa := newFakeAdam(t, devUUID)
	ac := newTestAdamClient(t, fa, devUUID)

	fa.receive(devMsg(1, 0))

	ch := make(chan *eveinfo.ZInfoMsg, 16)
	unsub, err := ac.SubscribeToDeviceInfoMsgs(devUUID, nil, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer unsub()

	expectNoMsg(t, ch)
	fa.receive(devMsg(2, 0))
	expectMsg(t, ch, devMsg(2, 0))
}

// A message Adam receives after the stream opens but before the history is
// read is in both, and must be delivered once.
func TestSubscribeWithLatestDeliversSeamMessageOnce(t *testing.T) {
	devUUID := uuid.Must(uuid.NewV4())
	fa := newFakeAdam(t, devUUID)
	ac := newTestAdamClient(t, fa, devUUID)

	fa.receive(devMsg(1, 0))
	fa.onStreamOpen = func() { fa.receive(devMsg(2, 0)) }

	ch := make(chan *eveinfo.ZInfoMsg, 16)
	unsub, err := ac.SubscribeToDeviceInfoMsgsWithLatest(devUUID, nil, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer unsub()

	expectMsg(t, ch, devMsg(2, 0))
	fa.receive(devMsg(3, 1))
	expectMsg(t, ch, devMsg(3, 1))
	expectNoMsg(t, ch)
}

// Messages Adam receives while the stream is down are delivered once the feed
// reconnects, followed by live ones.
func TestSubscribeFillsReconnectGap(t *testing.T) {
	devUUID := uuid.Must(uuid.NewV4())
	fa := newFakeAdam(t, devUUID)
	ac := newTestAdamClient(t, fa, devUUID)

	ch := make(chan *eveinfo.ZInfoMsg, 16)
	unsub, err := ac.SubscribeToDeviceInfoMsgs(devUUID, nil, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer unsub()

	fa.receive(devMsg(1, 0))
	expectMsg(t, ch, devMsg(1, 0))

	fa.dropStreams()
	fa.receive(devMsg(2, 1))
	expectMsg(t, ch, devMsg(2, 1))
	fa.receive(devMsg(3, 1))
	expectMsg(t, ch, devMsg(3, 1))
	expectNoMsg(t, ch)
}

func TestInfoFeedSharedAndReleased(t *testing.T) {
	devUUID := uuid.Must(uuid.NewV4())
	fa := newFakeAdam(t, devUUID)
	ac := newTestAdamClient(t, fa, devUUID)

	ch1 := make(chan *eveinfo.ZInfoMsg, 16)
	unsub1, err := ac.SubscribeToDeviceInfoMsgs(devUUID, nil, ch1)
	if err != nil {
		t.Fatal(err)
	}
	ch2 := make(chan *eveinfo.ZInfoMsg, 16)
	unsub2, err := ac.SubscribeToDeviceInfoMsgsWithLatest(devUUID, nil, ch2)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(ac.infoFeeds); n != 1 {
		t.Fatalf("got %d feeds, want 1", n)
	}

	fa.receive(devMsg(1, 0))
	expectMsg(t, ch1, devMsg(1, 0))
	expectMsg(t, ch2, devMsg(1, 0))

	unsub1()
	unsub1()
	if _, ok := <-ch1; ok {
		t.Fatal("channel not closed after unsubscribe")
	}
	fa.receive(devMsg(2, 0))
	expectMsg(t, ch2, devMsg(2, 0))

	unsub2()
	if n := len(ac.infoFeeds); n != 0 {
		t.Fatalf("got %d feeds after the last unsubscribe, want 0", n)
	}
}

func TestInfoMsgKey(t *testing.T) {
	full := appMsg(1, "a", eveinfo.ZSwState_RUNNING)
	deleted := &eveinfo.ZInfoMsg{
		Ztype:       eveinfo.ZInfoTypes_ZiApp,
		InfoContent: &eveinfo.ZInfoMsg_Ainfo{Ainfo: &eveinfo.ZInfoApp{AppID: "a"}},
	}
	if infoMsgKey(full) != infoMsgKey(deleted) {
		t.Errorf("deletion key %q differs from %q", infoMsgKey(deleted), infoMsgKey(full))
	}
	if infoMsgKey(full) == infoMsgKey(appMsg(1, "b", eveinfo.ZSwState_RUNNING)) {
		t.Error("different apps share a key")
	}
	if infoMsgKey(devMsg(1, 0)) != infoMsgKey(devMsg(2, 5)) {
		t.Error("device messages do not share a key")
	}
}
