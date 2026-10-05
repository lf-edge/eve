// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const infoFeedRetryDelay = 3 * time.Second

// infoFeed is the single source of info messages for one device, shared by
// all of the device's subscriptions. It reads one stream from Adam, keeps
// the latest message per reported object, and fans every new message out to
// its subscribers.
//
// Adam's stream carries only messages received after it was opened, so each
// time the stream is (re)opened the feed also reads Adam's stored history and
// applies every message it has not seen. Applying is idempotent, which makes
// the overlap between history and stream harmless and fills the gap a
// reconnect leaves.
type infoFeed struct {
	ac      *AdamClient
	devUUID uuid.UUID
	url     string
	refs    int // guarded by AdamClient.infoFeedsM

	cancel context.CancelFunc
	done   chan struct{}

	mu     sync.Mutex
	seq    uint64
	seen   map[[sha256.Size]byte]struct{}
	latest map[string]infoFeedEntry
	subs   map[*infoSub]struct{}
}

type infoFeedEntry struct {
	seq uint64
	msg *eveinfo.ZInfoMsg
}

// infoSub is one subscription to an infoFeed. The feed appends to its queue
// without blocking; the subscription's goroutine drains the queue into the
// subscriber's channel, so a slow subscriber delays only itself.
type infoSub struct {
	match func(msg *eveinfo.ZInfoMsg) bool
	mu    sync.Mutex
	queue []*eveinfo.ZInfoMsg
	wake  chan struct{}
}

func (s *infoSub) push(msgs ...*eveinfo.ZInfoMsg) {
	if len(msgs) == 0 {
		return
	}
	s.mu.Lock()
	s.queue = append(s.queue, msgs...)
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *infoSub) deliver(ctx context.Context, channel chan<- *eveinfo.ZInfoMsg) {
	defer close(channel)
	for {
		s.mu.Lock()
		queue := s.queue
		s.queue = nil
		s.mu.Unlock()
		for _, msg := range queue {
			if s.match != nil && !s.match(msg) {
				continue
			}
			select {
			case channel <- msg:
			case <-ctx.Done():
				return
			}
		}
		select {
		case <-s.wake:
		case <-ctx.Done():
			return
		}
	}
}

// infoMsgKey identifies the object an info message reports on. EVE reports a
// deleted object as its identifier with no other content, so a deletion
// replaces the object's entry like any other update. Messages without a
// per-object identifier (ZiDevice, ZiHardware, ...) describe the device as a
// whole and share one entry per content type.
func infoMsgKey(msg *eveinfo.ZInfoMsg) string {
	var id string
	switch content := msg.GetInfoContent().(type) {
	case *eveinfo.ZInfoMsg_Ainfo:
		id = content.Ainfo.GetAppID()
	case *eveinfo.ZInfoMsg_Niinfo:
		id = content.Niinfo.GetNetworkID()
	case *eveinfo.ZInfoMsg_Vinfo:
		id = content.Vinfo.GetUuid()
	case *eveinfo.ZInfoMsg_Cinfo:
		id = content.Cinfo.GetUuid()
	case *eveinfo.ZInfoMsg_Amdinfo:
		id = content.Amdinfo.GetUuid() + "/" + content.Amdinfo.GetType().String()
	case *eveinfo.ZInfoMsg_PatchInfo:
		id = content.PatchInfo.GetId()
	}
	return fmt.Sprintf("%s/%T/%s", msg.GetZtype(), msg.GetInfoContent(), id)
}

// newInfoFeed opens the device's info stream, seeds the feed from Adam's
// stored history and starts following the stream. It returns an error if
// either the stream or the history cannot be read.
func (ac *AdamClient) newInfoFeed(devUUID uuid.UUID) (*infoFeed, error) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &infoFeed{
		ac:      ac,
		devUUID: devUUID,
		url:     ac.adminURL("device/" + devUUID.String() + "/info"),
		cancel:  cancel,
		done:    make(chan struct{}),
		seen:    make(map[[sha256.Size]byte]struct{}),
		latest:  make(map[string]infoFeedEntry),
		subs:    make(map[*infoSub]struct{}),
	}
	resp, err := f.connect(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	go f.run(ctx, resp)
	return f, nil
}

// connect opens the stream and then applies the stored history. The order
// matters: a message arriving between the two is in both, and is applied
// once, whereas the reverse order would lose it.
func (f *infoFeed) connect(ctx context.Context) (*http.Response, error) {
	resp, err := f.ac.openStream(ctx, f.url)
	if err != nil {
		return nil, err
	}
	_, err = f.ac.fetchDeviceInfoMsgs(ctx, f.devUUID,
		func(msg *eveinfo.ZInfoMsg) (bool, error) {
			f.apply(msg)
			return false, nil
		})
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	return resp, nil
}

func (f *infoFeed) run(ctx context.Context, resp *http.Response) {
	defer close(f.done)
	for {
		if resp == nil {
			select {
			case <-time.After(infoFeedRetryDelay):
			case <-ctx.Done():
				return
			}
			var err error
			resp, err = f.connect(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				f.ac.log.Errorf("failed to reopen info message stream: %v", err)
				continue
			}
		}
		f.follow(ctx, resp)
		resp = nil
	}
}

// follow applies streamed messages until the stream ends.
func (f *infoFeed) follow(ctx context.Context, resp *http.Response) {
	defer func() {
		if err := resp.Body.Close(); err != nil {
			f.ac.log.Warnf("failed to close response body: %v", err)
		}
	}()
	dec := json.NewDecoder(resp.Body)
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, io.EOF) {
				f.ac.log.Warn("info message stream closed by server")
				return
			}
			f.ac.log.Errorf("failed to decode streamed info message: %v", err)
			return
		}
		msg := &eveinfo.ZInfoMsg{}
		if err := protojson.Unmarshal(raw, msg); err != nil {
			f.ac.log.Errorf("failed to proto-unmarshal streamed info message: %v", err)
			continue
		}
		f.apply(msg)
	}
}

// apply records msg as the latest for its object and hands it to every
// subscriber, unless the feed has already applied an identical message. EVE
// stamps every info message with its send time, so identical content means
// the same message read twice.
func (f *infoFeed) apply(msg *eveinfo.ZInfoMsg) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if b, err := (proto.MarshalOptions{Deterministic: true}).Marshal(msg); err == nil {
		sum := sha256.Sum256(b)
		if _, dup := f.seen[sum]; dup {
			return
		}
		f.seen[sum] = struct{}{}
	}
	f.seq++
	f.latest[infoMsgKey(msg)] = infoFeedEntry{seq: f.seq, msg: msg}
	for s := range f.subs {
		s.push(msg)
	}
}

// addSub registers a subscription. With withLatest, the subscription first
// receives the latest message of every object, in the order they arrived;
// every message applied afterwards follows it.
func (f *infoFeed) addSub(s *infoSub, withLatest bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if withLatest {
		entries := make([]infoFeedEntry, 0, len(f.latest))
		for _, e := range f.latest {
			entries = append(entries, e)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].seq < entries[j].seq })
		msgs := make([]*eveinfo.ZInfoMsg, len(entries))
		for i, e := range entries {
			msgs[i] = e.msg
		}
		s.push(msgs...)
	}
	f.subs[s] = struct{}{}
}

func (f *infoFeed) removeSub(s *infoSub) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.subs, s)
}

func (f *infoFeed) stop() {
	f.cancel()
	<-f.done
}

// acquireInfoFeed returns the device's feed, creating it on first use.
// Every call must be paired with releaseInfoFeed.
func (ac *AdamClient) acquireInfoFeed(devUUID uuid.UUID) (*infoFeed, error) {
	ac.infoFeedsM.Lock()
	defer ac.infoFeedsM.Unlock()
	f, ok := ac.infoFeeds[devUUID]
	if !ok {
		var err error
		f, err = ac.newInfoFeed(devUUID)
		if err != nil {
			return nil, err
		}
		ac.infoFeeds[devUUID] = f
	}
	f.refs++
	return f, nil
}

// releaseInfoFeed drops one reference and stops the feed with the last one.
// A later subscription builds a new feed from Adam's history, which still
// holds everything the stopped one had seen.
func (ac *AdamClient) releaseInfoFeed(f *infoFeed) {
	ac.infoFeedsM.Lock()
	f.refs--
	last := f.refs == 0
	if last {
		delete(ac.infoFeeds, f.devUUID)
	}
	ac.infoFeedsM.Unlock()
	if last {
		f.stop()
	}
}

func (ac *AdamClient) subscribeToDeviceInfoMsgs(devUUID uuid.UUID,
	match func(msg *eveinfo.ZInfoMsg) bool, channel chan<- *eveinfo.ZInfoMsg,
	withLatest bool) (unsubscribe func(), err error) {
	if err = ac.checkAdamRunning(); err != nil {
		return nil, err
	}
	ac.mutex.Lock()
	_, known := ac.knownDevices[devUUID]
	ac.mutex.Unlock()
	if !known {
		return nil, fmt.Errorf("unknown device UUID %q", devUUID)
	}

	f, err := ac.acquireInfoFeed(devUUID)
	if err != nil {
		return nil, err
	}
	s := &infoSub{match: match, wake: make(chan struct{}, 1)}
	f.addSub(s, withLatest)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.deliver(ctx, channel)
	}()

	var once sync.Once
	unsubscribe = func() {
		once.Do(func() {
			f.removeSub(s)
			cancel()
			wg.Wait()
			ac.releaseInfoFeed(f)
		})
	}
	return unsubscribe, nil
}
