// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package socketdriver

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	logutils "github.com/lf-edge/eve/pkg/pillar/utils/logging"
	"github.com/lf-edge/eve/pkg/pillar/watch"
	"github.com/sirupsen/logrus"
)

// Subscriber implementation of `pubsub.DriverSubscriber` for `SocketDriver`.
// Implements Unix-domain socket or directory subscription,
// and directory-based persistence.
type Subscriber struct {
	sockName         string   // there is one socket per publishing agent
	sock             net.Conn // For socket subscriptions
	subscribeFromDir bool     // Handle special case of file only info
	name             string
	topic            string
	dirName          string
	C                chan<- pubsub.Change
	logger           *logrus.Logger
	log              *base.LogObject
	doneChan         chan struct{}
}

// Load load entire persisted data set into a map
func (s *Subscriber) Load() (map[string][]byte, bool, error) {
	dirName := s.dirName
	foundRestarted := false
	items := make(map[string][]byte)

	s.log.Debugf("Load(%s)\n", s.name)

	files, err := ioutil.ReadDir(dirName)
	if err != nil {
		// Drive on?
		s.log.Error(err)
		return items, foundRestarted, err
	}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			if file.Name() == "restarted" {
				foundRestarted = true
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

		s.log.Debugf("Load found key %s file %s\n", key, statusFile)

		sb, err := ioutil.ReadFile(statusFile)
		if err != nil {
			s.log.Errorf("Load: %s for %s\n", err, statusFile)
			continue
		}
		items[key] = sb
	}
	return items, foundRestarted, err
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
		s.log.Infof("Creating %s at %s", "watch.WatchStatus",
			logutils.GetMyStack())
		go watch.WatchStatus(s.log, s.dirName, true, s.doneChan,
			translator)
		s.log.Infof("Creating %s at %s", "s.Translate",
			logutils.GetMyStack())
		go s.translate(translator, s.C)
		return nil
	} else if subscribeFromSock {
		s.log.Infof("Creating %s at %s", "s.watchSock",
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
	s.log.Infof("Stop(%s)", s.name)
	// We handle both subscribeFromDir and subscribeFromSock
	if s.subscribeFromDir {
		// Tell watch.WatchStatus to finish and close the translator
		// channel which in turn will make the translator finish.
		close(s.doneChan)
		return nil
	} else if subscribeFromSock {
		// Tell watchSock to finish
		close(s.doneChan)
		if s.sock != nil {
			// Force connectAndRead to terminate
			s.log.Warnf("Stop(%s): forcing socket closed",
				s.name)
			s.sock.Close()
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
		maybeLogAllocated(s.log)
		switch msg {
		case "hello":
			// Do nothing
		case "complete":
			// XXX to handle restart we need to handle "complete"
			// by doing a sweep across the KeyMap to handleDelete
			// what we didn't see before the "complete"
			s.C <- pubsub.Change{Operation: pubsub.Create, Key: "done"}

		case "restarted":
			s.C <- pubsub.Change{Operation: pubsub.Restart, Key: "done"}

		case "delete":
			s.C <- pubsub.Change{Operation: pubsub.Delete, Key: key}

		case "update":
			// XXX is size of val any issue? pointer?
			s.C <- pubsub.Change{Operation: pubsub.Modify, Key: key, Value: val}
		case "done":
			s.log.Warnf("watchSock(%s) goroutine exiting", s.name)
			return
		}
	}
}

// Returns msg, key, val
// key and val are base64-encoded
func (s *Subscriber) connectAndRead() (string, string, []byte) {
	delay := time.Duration(0)
	// Waiting for publisher to appear; retry on error
	for {
		if areWeDone(s.log, s.doneChan) {
			s.log.Infof("connectAndRead(%s) done", s.name)
			return "done", "", nil
		}
		if delay != 0 {
			time.Sleep(delay)
			delay = time.Duration(0)
			if areWeDone(s.log, s.doneChan) {
				s.log.Infof("connectAndRead(%s) done", s.name)
				return "done", "", nil
			}
		}
		if s.sock == nil {
			sock, err := net.Dial("unixpacket", s.sockName)
			if err != nil {
				errStr := fmt.Sprintf("connectAndRead(%s): Dial failed %s",
					s.name, err)
				// During startup and after a publisher has
				// exited we get these failures; treat
				// as debug
				s.log.Debugln(errStr)
				delay = 10 * time.Second
				continue
			}
			s.sock = sock
			req := fmt.Sprintf("request %s", s.topic)
			_, err = sock.Write([]byte(req))
			if err != nil {
				errStr := fmt.Sprintf("connectAndRead(%s): sock write failed %s",
					s.name, err)
				s.log.Errorln(errStr)
				s.sock.Close()
				s.sock = nil
				continue
			}
		}
		if areWeDone(s.log, s.doneChan) {
			s.log.Infof("connectAndRead(%s) done", s.name)
			return "done", "", nil
		}

		// wait for readable conn
		// We close s.sock when we close s.doneChan to make sure
		// ConnReadCheck unblocks
		if err := pubsub.ConnReadCheck(s.sock); err != nil {
			errStr := fmt.Sprintf("connectAndRead(%s) ConnReadCheck failed: %s",
				s.name, err)
			s.log.Errorln(errStr)
			s.sock.Close()
			s.sock = nil
			continue
		}
		msg, key, val := s.read()
		if msg == "" {
			continue
		}
		return msg, key, val
	}
}

// Returns msg, key, val
// key and val are base64-encoded
// msg is "" if there is nothing to process
func (s *Subscriber) read() (string, string, []byte) {

	buf, doneFunc := GetBuffer()
	defer doneFunc()

	res, err := s.sock.Read(buf)
	if err != nil {
		errStr := fmt.Sprintf("connectAndRead(%s): sock read failed %s",
			s.name, err)
		s.log.Errorln(errStr)
		s.sock.Close()
		s.sock = nil
		return "", "", nil
	}

	if res == len(buf) {
		// Likely truncated
		// Peer process could have died
		s.log.Errorf("connectAndRead(%s) request likely truncated\n", s.name)
		return "", "", nil
	}
	reply := strings.Split(string(buf[0:res]), " ")
	count := len(reply)
	if count < 2 {
		errStr := fmt.Sprintf("connectAndRead(%s): too short read", s.name)
		s.log.Errorln(errStr)
		return "", "", nil
	}
	msg := reply[0]
	t := reply[1]

	if t != s.topic {
		errStr := fmt.Sprintf("connectAndRead(%s): mismatched topic %s vs. %s for %s", s.name, t, s.topic, msg)
		s.log.Errorln(errStr)
		// XXX return "", "", nil?
	}

	// XXX are there error cases where we should Close and
	// continue aka reconnect?
	switch msg {
	case "hello", "restarted", "complete":
		s.log.Debugf("connectAndRead(%s) Got message %s type %s\n", s.name, msg, t)
		return msg, "", nil

	case "delete":
		if count < 3 {
			errStr := fmt.Sprintf("connectAndRead(%s): too short delete", s.name)
			s.log.Errorln(errStr)
			return "", "", nil
		}
		recvKey := reply[2]

		key, err := base64.StdEncoding.DecodeString(recvKey)
		if err != nil {
			errStr := fmt.Sprintf("connectAndRead(%s): base64 failed %s", s.name, err)
			s.log.Errorln(errStr)
			return "", "", nil
		}
		if s.logger.GetLevel() == logrus.TraceLevel {
			s.log.Debugf("connectAndRead(%s): delete type %s key %s\n", s.name, t, string(key))
		}
		return msg, string(key), nil

	case "update":
		if count != 4 {
			errStr := fmt.Sprintf("connectAndRead(%s): update of %d parts instead of expected 4", s.name, count)
			s.log.Errorln(errStr)
			return "", "", nil
		}
		recvKey := reply[2]
		recvVal := reply[3]
		key, err := base64.StdEncoding.DecodeString(recvKey)
		if err != nil {
			errStr := fmt.Sprintf("connectAndRead(%s): base64 key failed %s", s.name, err)
			s.log.Errorln(errStr)
			return "", "", nil
		}
		val, err := base64.StdEncoding.DecodeString(recvVal)
		if err != nil {
			errStr := fmt.Sprintf("connectAndRead(%s): base64 val failed %s", s.name, err)
			s.log.Errorln(errStr)
			return "", "", nil
		}
		if s.logger.GetLevel() == logrus.TraceLevel {
			s.log.Debugf("connectAndRead(%s): update type %s key %s val %s\n", s.name, t, string(key), string(val))
		}
		return msg, string(key), val

	default:
		errStr := fmt.Sprintf("connectAndRead(%s): unknown message %s", s.name, msg)
		s.log.Errorln(errStr)
		return "", "", nil
	}
}

func (s *Subscriber) translate(in <-chan string, out chan<- pubsub.Change) {
	statusDirName := s.dirName
	for change := range in {
		s.log.Debugf("translate received message '%s'", change)
		operation := string(change[0])
		fileName := string(change[2:])
		// Remove .json from name */
		name := strings.Split(fileName, ".json")
		switch {
		case operation == "R":
			s.log.Infof("Received restart <%s>\n", fileName)
			// I do not know why, but the "R" operation from the file watcher
			// historically called the Complete operation, leading to the
			// "Synchronized" handler being called.
			out <- pubsub.Change{Operation: pubsub.Create}
		case operation == "M" && fileName == "restarted":
			s.log.Debugf("Found restarted file\n")
			out <- pubsub.Change{Operation: pubsub.Restart}
		case !strings.HasSuffix(fileName, ".json"):
			// s.log.Debugf("Ignoring file <%s> operation %s\n",
			//	fileName, operation)
			continue
		case operation == "D":
			out <- pubsub.Change{Operation: pubsub.Delete, Key: name[0]}
		case operation == "M":
			statusFile := path.Join(statusDirName, fileName)
			cb, err := ioutil.ReadFile(statusFile)
			if err != nil {
				s.log.Errorf("%s for %s\n", err, statusFile)
				continue
			}
			out <- pubsub.Change{Operation: pubsub.Modify, Key: name[0], Value: cb}
		default:
			s.log.Fatal("Unknown operation from Watcher: ", operation)
		}
	}
	s.log.Warnf("translate goroutine exiting")
	close(out)
}
