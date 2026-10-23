// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package socketdriver

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	logutils "github.com/lf-edge/eve/pkg/pillar/utils/logging"
	"github.com/lf-edge/eve/pkg/pillar/watch"
	"github.com/sirupsen/logrus"
)

// Subscriber implementation of `pubsub.DriverSubscriber` for `SocketDriver`.
// Implements Unix-domain socket or directory subscription,
// and directory-based persistence.
type Subscriber struct {
	sockName         string       // there is one socket per publishing agent
	sockMu           sync.Mutex   // guards writes of sock against Stop
	sock             net.Conn     // For socket subscriptions
	protoReported    bool         // a wire protocol mismatch was logged
	reader           *FrameReader // reads the frames from sock
	stats            *pubsub.SubStats
	subscribeFromDir bool // Handle special case of file only info
	persistent       bool // initial Load() is from the persistent dir
	name             string
	topic            string
	dirName          string
	C                chan<- pubsub.Change
	logger           *logrus.Logger
	log              *base.LogObject
	doneChan         chan struct{}
	rootDir          string
}

// Load load entire persisted data set into a map
func (s *Subscriber) Load() (map[string][]byte, int, error) {
	dirName := s.dirName
	restartCounter := 0
	items := make(map[string][]byte)

	s.log.Tracef("Load(%s)\n", s.name)

	files, err := os.ReadDir(dirName)
	if err != nil {
		// Drive on?
		s.log.Error(err)
		return items, restartCounter, err
	}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			if file.Name() == "restarted" {
				statusFile := dirName + "/" + file.Name()
				sb, err := os.ReadFile(statusFile)
				if err != nil {
					s.log.Errorf("Load: %s for %s\n", err, statusFile)
					continue
				}
				restartCounter, err = strconv.Atoi(string(sb))
				// Treat present but empty file as "1" to
				// handle old file in /persist
				if err != nil {
					s.log.Warnf("Load: %s for %s; treat as 1", err, statusFile)
					restartCounter = 1
				}
			}
			continue
		}
		// Remove .json from name */
		key := strings.Split(file.Name(), ".json")[0]

		statusFile := dirName + "/" + file.Name()
		if _, err := os.Stat(statusFile); err != nil {
			// File just vanished!
			s.log.Errorf("populate: File disappeared <%s>\n",
				statusFile)
			continue
		}

		s.log.Tracef("Load found key %s file %s\n", key, statusFile)

		sb, err := os.ReadFile(statusFile)
		if err != nil {
			s.log.Errorf("Load: %s for %s\n", err, statusFile)
			continue
		}
		items[key] = sb
	}
	return items, restartCounter, err
}

// Start start the subscriber listening on the given name and topic
// internally, will watch for changes on either the socket or the file, and then
// send the change summary to s.C
func (s *Subscriber) Start() error {
	// We handle both subscribeFromDir and subscribeFromSock
	// Note that change filename includes .json for subscribeFromDir. That
	// is removed by the translator.
	if s.subscribeFromDir {
		// Waiting for directory to appear
		for {
			if _, err := os.Stat(s.dirName); err != nil {
				errStr := fmt.Sprintf("Subscribe(%s): failed %s; waiting", s.name, err)
				s.log.Errorln(errStr)
				time.Sleep(10 * time.Second)
			} else {
				break
			}
		}
		// WatchStatus updates the channel with messages in a slightly different
		// format than the standard for pubsub
		// we pass it through a translator
		translator := make(chan string)
		s.log.Functionf("Creating %s at %s", "watch.WatchStatus",
			logutils.GetMyStack())
		go watch.WatchStatus(s.log, s.dirName, true, s.doneChan,
			translator)
		s.log.Functionf("Creating %s at %s", "s.Translate",
			logutils.GetMyStack())
		go s.translate(translator, s.C)
		return nil
	} else if subscribeFromSock {
		s.log.Functionf("Creating %s at %s", "s.watchSock",
			logutils.GetMyStack())
		go s.watchSock()
		return nil
	} else {
		errStr := fmt.Sprintf("Subscribe(%s): failed %s", s.name, "nowhere to subscribe")
		return errors.New(errStr)
	}
}

// Stop the subscriber listening on the given name and topic
func (s *Subscriber) Stop() error {
	s.log.Functionf("Stop(%s)", s.name)
	// We handle both subscribeFromDir and subscribeFromSock
	if s.subscribeFromDir {
		// Tell watch.WatchStatus to finish and close the translator
		// channel which in turn will make the translator finish.
		close(s.doneChan)
		return nil
	} else if subscribeFromSock {
		// Tell watchSock to finish
		close(s.doneChan)
		s.sockMu.Lock()
		sock := s.sock
		s.sockMu.Unlock()
		if sock != nil {
			// Force connectAndRead to terminate
			s.log.Warnf("Stop(%s): forcing socket closed",
				s.name)
			sock.Close()
		}
		return nil
	} else {
		errStr := fmt.Sprintf("Subscribe(%s): failed %s",
			s.name, "nowhere to stop")
		return errors.New(errStr)
	}
}

func (s *Subscriber) watchSock() {
	for {
		msg, key, val := s.connectAndRead()
		switch msg {
		case "hello":
			// Do nothing
		case "complete":
			// XXX to handle connection/process restart we need to handle "sync"
			// by doing a sweep across the KeyMap to handleDelete
			// what we didn't see before the "complete"
			s.C <- pubsub.Change{Operation: pubsub.Sync, Key: "done"}

		case "restarted":
			s.C <- pubsub.Change{Operation: pubsub.Restart,
				Key: key}

		case "delete":
			s.C <- pubsub.Change{Operation: pubsub.Delete, Key: key}

		case "update":
			// XXX is size of val any issue? pointer?
			s.C <- pubsub.Change{Operation: pubsub.Modify, Key: key, Value: val}
		case "done":
			if s.sock != nil {
				s.disconnect()
			}
			s.log.Warnf("watchSock(%s) goroutine exiting", s.name)
			return
		}
	}
}

// Returns msg, key, val
func (s *Subscriber) connectAndRead() (string, string, []byte) {
	delay := time.Duration(0)
	// Waiting for publisher to appear; retry on error
	for {
		if areWeDone(s.log, s.doneChan) {
			s.log.Functionf("connectAndRead(%s) done", s.name)
			return "done", "", nil
		}
		if delay != 0 {
			time.Sleep(delay)
			delay = time.Duration(0)
			if areWeDone(s.log, s.doneChan) {
				s.log.Functionf("connectAndRead(%s) done", s.name)
				return "done", "", nil
			}
		}
		if s.sock == nil {
			sock, err := net.Dial("unix", s.sockName)
			if err != nil {
				errStr := fmt.Sprintf("connectAndRead(%s): Dial failed %s",
					s.name, err)
				if errors.Is(err, syscall.EPROTOTYPE) {
					// The publisher listens on a socket of another
					// type: it speaks a different pubsub wire protocol.
					if !s.protoReported {
						s.log.Errorf("%s: the publisher speaks a different pubsub "+
							"wire protocol; is its component out of date?", errStr)
						s.protoReported = true
					}
				} else {
					// During startup and after a publisher has
					// exited we get these failures; treat
					// as debug
					s.log.Traceln(errStr)
				}
				delay = 10 * time.Second
				continue
			}
			s.sockMu.Lock()
			s.sock = sock
			s.sockMu.Unlock()
			s.reader = NewFrameReaderWithStats(sock, s.stats)
			s.stats.Subscribers.Add(1)
			req := fmt.Sprintf("request %s", s.topic)
			s.stats.AllocDecode.Add(len(req))
			s.stats.AllocDecode.Add(len(req))
			err = writeFrame(sock, []byte(req), false, &s.stats.AllocDecode)
			if err != nil {
				errStr := fmt.Sprintf("connectAndRead(%s): sock write failed %s",
					s.name, err)
				s.log.Errorln(errStr)
				s.disconnect()
				continue
			}
		}
		if areWeDone(s.log, s.doneChan) {
			s.log.Functionf("connectAndRead(%s) done", s.name)
			return "done", "", nil
		}

		// read blocks until a frame arrives. We close s.sock when we
		// close s.doneChan to make sure it unblocks.
		msg, key, val := s.read()
		if msg == "" {
			continue
		}
		return msg, key, val
	}
}

// Returns msg, key, val
// msg is "" if there is nothing to process
func (s *Subscriber) read() (string, string, []byte) {

	frame, err := s.reader.ReadFrame()
	if err != nil {
		errStr := fmt.Sprintf("connectAndRead(%s): sock read failed %s",
			s.name, err)
		s.log.Errorln(errStr)
		s.disconnect()
		return "", "", nil
	}
	defer s.reader.Release()

	// The value of an update is the last field and may contain spaces.
	// The frame is reused by the next read, hence everything returned
	// is copied out of it.
	reply := bytes.SplitN(frame, []byte(" "), 4)
	s.stats.AllocDecode.Add(cap(reply) * 24)
	count := len(reply)
	if count < 2 {
		errStr := fmt.Sprintf("connectAndRead(%s): too short read", s.name)
		s.log.Errorln(errStr)
		return "", "", nil
	}
	msg := string(reply[0])
	t := string(reply[1])
	addString(&s.stats.AllocDecode, len(msg))
	addString(&s.stats.AllocDecode, len(t))

	if t != s.topic {
		errStr := fmt.Sprintf("connectAndRead(%s): mismatched topic %s vs. %s for %s", s.name, t, s.topic, msg)
		s.log.Errorln(errStr)
		// XXX return "", "", nil?
	}

	// XXX are there error cases where we should Close and
	// continue aka reconnect?
	switch msg {
	case "hello", "complete":
		s.log.Tracef("connectAndRead(%s) Got message %s type %s\n", s.name, msg, t)
		if msg == "hello" && count >= 3 {
			s.stats.AllocDecode.AddTemp(len(reply[2]))
			s.checkPublisherPersistence(string(reply[2]))
		}
		return msg, "", nil

	case "restarted":
		if count < 3 {
			errStr := fmt.Sprintf("connectAndRead(%s): too short restarted", s.name)
			s.log.Errorln(errStr)
			return "", "", nil
		}
		counter := string(reply[2])
		addString(&s.stats.AllocDecode, len(counter))
		s.log.Tracef("connectAndRead(%s) Got message %s type %s counter %s", s.name, msg, t, counter)
		return msg, counter, nil

	case "delete":
		if count < 3 {
			errStr := fmt.Sprintf("connectAndRead(%s): too short delete", s.name)
			s.log.Errorln(errStr)
			return "", "", nil
		}
		recvKey := reply[2]

		s.stats.AllocDecode.Add(base64.StdEncoding.DecodedLen(len(recvKey)))
		key, err := base64.StdEncoding.AppendDecode(nil, recvKey)
		if err != nil {
			errStr := fmt.Sprintf("connectAndRead(%s): base64 failed %s", s.name, err)
			s.log.Errorln(errStr)
			return "", "", nil
		}
		if s.logger.GetLevel() == logrus.TraceLevel {
			s.log.Tracef("connectAndRead(%s): delete type %s key %s\n", s.name, t, string(key))
		}
		addString(&s.stats.AllocDecode, len(key))
		return msg, string(key), nil

	case "update":
		if count != 4 {
			errStr := fmt.Sprintf("connectAndRead(%s): update of %d parts instead of expected 4", s.name, count)
			s.log.Errorln(errStr)
			return "", "", nil
		}
		recvKey := reply[2]
		recvVal := reply[3]
		s.stats.AllocDecode.Add(base64.StdEncoding.DecodedLen(len(recvKey)))
		key, err := base64.StdEncoding.AppendDecode(nil, recvKey)
		if err != nil {
			errStr := fmt.Sprintf("connectAndRead(%s): base64 key failed %s", s.name, err)
			s.log.Errorln(errStr)
			return "", "", nil
		}
		// A frame in a buffer of its own, a large or decompressed one, is
		// not reused: keep the value in it instead of copying it out.
		val := recvVal
		if !s.reader.Owned() {
			val = bytes.Clone(recvVal)
			s.stats.AllocDecode.Add(len(recvVal))
		}
		if s.logger.GetLevel() == logrus.TraceLevel {
			s.log.Tracef("connectAndRead(%s): update type %s key %s val %s\n", s.name, t, string(key), string(val))
		}
		addString(&s.stats.AllocDecode, len(key))
		return msg, string(key), val

	default:
		errStr := fmt.Sprintf("connectAndRead(%s): unknown message %s", s.name, msg)
		s.log.Errorln(errStr)
		return "", "", nil
	}
}

// disconnect closes the connection to the publisher.
func (s *Subscriber) disconnect() {
	s.sock.Close()
	s.sockMu.Lock()
	s.sock = nil
	s.sockMu.Unlock()
	s.reader.Release()
	s.stats.Subscribers.Add(-1)
}

// checkPublisherPersistence compares the publisher's persistence, as
// advertised in its hello message, with the Persistent option of this
// subscription. A persistent subscription to a non-persistent publication is
// a bug: the initial Load() done by Activate() reads from the persistent
// directory which the publisher never writes, so it silently loads nothing,
// or worse, stale state left behind by an older EVE version.
func (s *Subscriber) checkPublisherPersistence(pubPersistent string) {
	persistent, err := strconv.ParseBool(pubPersistent)
	if err != nil {
		s.log.Errorf("checkPublisherPersistence(%s): malformed persistence flag %q in hello message",
			s.name, pubPersistent)
		return
	}
	if s.persistent && !persistent {
		s.log.Errorf("checkPublisherPersistence(%s): subscription for topic %s is persistent, "+
			"but the publisher is not; the initial load of this subscription is unreliable "+
			"(empty or stale data); fix the Persistent flag on one of the two sides",
			s.name, s.topic)
	}
}

// translate takes file notifications from a file watcher and converts them
// pubsub operations. Normally this is 1-1 but since the file watcher can not
// ensure ordering for the restarted file we delay those until a bit to ensure
// they are delivered after any notifications for other files.
func (s *Subscriber) translate(in <-chan string, out chan<- pubsub.Change) {
	statusDirName := s.dirName
	gotRestarted := false
	var restartedValue string

	// Delay sending restarted until we have seen other changes
	interval := 3 * time.Second
	maxDelay := float64(interval)
	minDelay := maxDelay / 3
	ticker := flextimer.NewRangeTicker(time.Duration(1000*minDelay),
		time.Duration(1000*maxDelay))

	for {
		select {
		case _, ok := <-ticker.C:
			if !ok || !gotRestarted {
				// skip handling in case of closed or not restarted
				break
			}
			out <- pubsub.Change{Operation: pubsub.Restart, Key: restartedValue}
			s.log.Functionf("sent restarted file with %s",
				restartedValue)
			gotRestarted = false
			restartedValue = ""
			ticker.UpdateRangeTicker(time.Duration(1000*minDelay),
				time.Duration(1000*maxDelay))

		case change, ok := <-in:
			if !ok {
				if gotRestarted {
					out <- pubsub.Change{Operation: pubsub.Restart, Key: restartedValue}
					s.log.Warnf("translate goroutine exiting flushed restarted %s",
						restartedValue)
					gotRestarted = false
					restartedValue = ""
				} else {
					s.log.Warnf("translate goroutine exiting")
				}
				close(out)
				ticker.StopTicker()
				return
			}
			s.log.Tracef("translate received message '%s'", change)
			operation := string(change[0])
			fileName := string(change[2:])
			// Remove .json from name */
			name := strings.Split(fileName, ".json")
			switch {
			case operation == "R":
				s.log.Functionf("Received restart <%s>", fileName)
				// I do not know why, but the "R" operation from the file watcher
				// historically called the Complete operation, leading to the
				// "Synchronized" handler being called.
				out <- pubsub.Change{Operation: pubsub.Sync}
			case operation == "M" && fileName == "restarted":
				statusFile := path.Join(statusDirName, fileName)
				cb, err := os.ReadFile(statusFile)
				if err != nil {
					s.log.Errorf("%s for %s\n", err, statusFile)
					continue
				}
				// Should we send a previous restarted?
				if gotRestarted {
					out <- pubsub.Change{Operation: pubsub.Restart, Key: restartedValue}
					s.log.Functionf("flush restarted queued %s new %s",
						restartedValue, string(cb))
				}
				gotRestarted = true
				restartedValue = string(cb)
				s.log.Functionf("Starting timer restarted %s for %v %v",
					restartedValue,
					time.Duration(minDelay), time.Duration(maxDelay))
				ticker.UpdateRangeTicker(time.Duration(minDelay),
					time.Duration(maxDelay))

			case !strings.HasSuffix(fileName, ".json"):
				// s.log.Tracef("Ignoring file <%s> operation %s\n",
				//	fileName, operation)
				continue
			case operation == "D":
				out <- pubsub.Change{Operation: pubsub.Delete, Key: name[0]}
				s.log.Tracef("sent delete file for %s",
					name[0])
			case operation == "M":
				statusFile := path.Join(statusDirName, fileName)
				cb, err := os.ReadFile(statusFile)
				if err != nil {
					s.log.Errorf("%s for %s\n", err, statusFile)
					continue
				}
				out <- pubsub.Change{Operation: pubsub.Modify, Key: name[0], Value: cb}
				s.log.Tracef("sent modify file for %s",
					name[0])
			default:
				s.log.Fatal("Unknown operation from Watcher: ", operation)
			}
		}
	}
}

// addString counts a string(b) conversion of n bytes which escapes: Go
// does not allocate for strings of one byte or less.
func addString(a *pubsub.Alloc, n int) {
	if n > 1 {
		a.Add(n)
	}
}
