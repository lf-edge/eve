// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package socketdriver

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	logutils "github.com/lf-edge/eve/pkg/pillar/utils/logging"
	"github.com/sirupsen/logrus"
)

// Publisher implementation of `pubsub.DriverPublisher` for `SocketDriver`.
// Implements Unix-domain socket or directory publication,
// and directory-based persistence.
type Publisher struct {
	persistent     bool
	sock           net.Conn // For socket subscriptions
	sockName       string   // there is one socket per publishing agent
	listener       net.Listener
	dirName        string
	shouldPopulate bool // indicate on start if we need to populate
	name           string
	topic          string
	updaters       *pubsub.Updaters
	differ         pubsub.Differ
	restarted      pubsub.Restarted
	logger         *logrus.Logger
	log            *base.LogObject
	doneChan       chan struct{}
	rootDir        string
	largestSent    atomic.Int64 // largest message above warnSize sent so far
	stats          *pubsub.PubStats
}

const maxFileName = 255

// warnSize is the message size above which the publisher logs a warning, so
// that a value growing towards maxsize is noticed before it reaches it.
const warnSize = 64 * 1024

// Publish publish a key-value pair
func (s *Publisher) Publish(key string, item []byte) error {
	if len(item) == 0 {
		return fmt.Errorf("empty content published for %s/%s", s.name, key)
	}
	if strings.Contains(key, "/") {
		return fmt.Errorf("key(%s) must not contain slashes", key)
	}
	if len(key+".json") > maxFileName {
		return fmt.Errorf("key(%s) exceed maximum filename limit of %d bytes: %d",
			key, maxFileName, len(key+".json"))
	}
	fileName := s.dirName + "/" + key + ".json"
	s.log.Tracef("Publish writing %s\n", fileName)

	var err error
	if s.persistent {
		err = fileutils.WriteRenameWithBackup(fileName, item)
	} else {
		err = fileutils.WriteRename(fileName, item)
	}
	if err != nil {
		return err
	}
	return nil
}

// Unpublish delete a key and publish its deletion
func (s *Publisher) Unpublish(key string) error {
	fileName := s.dirName + "/" + key + ".json"
	s.log.Tracef("Unpublish deleting file %s\n", fileName)

	// First remove backup file so that unpublished item will not be accidentally recovered.
	if s.persistent {
		err := os.Remove(fileName + ".bak")
		// Ignore if backup file is missing.
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("Unpublish(%s/%s): failed to remove backup: %w",
				s.name, key, err)
		}
	}

	if err := os.Remove(fileName); err != nil {
		return fmt.Errorf("Unpublish(%s/%s): failed: %w", s.name, key, err)
	}
	if err := fileutils.DirSync(s.dirName); err != nil {
		return fmt.Errorf("Unpublish(%s/%s): failed to sync directory %s: %w",
			s.name, key, s.dirName, err)
	}
	return nil
}

// Load load entire persisted data set into a map
func (s *Publisher) Load() (map[string][]byte, int, error) {
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
		if len(sb) == 0 {
			s.log.Errorf("Load: %s is empty", statusFile)
			continue
		}
		items[key] = sb
	}

	// Try to recover lost items (have backup but missing the original).
	if s.persistent {
		const backupSuffix = ".json.bak"
		var keysToRecover []string
		for _, file := range files {
			if strings.HasSuffix(file.Name(), backupSuffix) {
				key := strings.TrimSuffix(file.Name(), backupSuffix)
				if _, loaded := items[key]; !loaded {
					keysToRecover = append(keysToRecover, key)
				}
			}
		}
		for _, key := range keysToRecover {
			sb, err := s.recoverFromBackup(key)
			if err != nil {
				s.log.Errorf("Failed to recover %s/%s: %v", s.name, key, err)
				continue
			}
			items[key] = sb
			s.log.Warnf("Using backup of %s/%s", s.name, key)
		}
	}
	return items, restartCounter, err
}

// recoverFromBackup tries to recover lost item from a backup file.
// Called when the original file is missing or empty.
func (s *Publisher) recoverFromBackup(key string) ([]byte, error) {
	origFileName := s.dirName + "/" + key + ".json"
	backupFileName := origFileName + ".bak"
	bakData, err := os.ReadFile(backupFileName)
	if err != nil {
		err = fmt.Errorf("failed to read backup file %s: %w", backupFileName, err)
		return nil, err
	}
	if len(bakData) == 0 {
		err = fmt.Errorf("empty backup file %s: %w", backupFileName, err)
		return nil, err
	}
	if err := fileutils.WriteRename(origFileName, bakData); err != nil {
		err = fmt.Errorf("failed to overwrite %s with backup data: %w", origFileName, err)
		return nil, err
	}
	return bakData, nil
}

// Start start publishing on the socket
func (s *Publisher) Start() error {
	// we only do this for not publishing to dir, and publishing to socket
	// which already was indicated by having the listener set up
	if s.listener == nil {
		return nil
	}
	s.log.Functionf("Creating %s at %s", "func", logutils.GetMyStack())
	go func(s *Publisher) {
		instance := 0
		done := false
		for !done {
			if areWeDone(s.log, s.doneChan) {
				done = true
				continue
			}
			// We interrupt this accept by closing s.listener
			// when we close s.doneChan
			c, err := s.listener.Accept()
			if err != nil {
				s.log.Errorf("publisher(%s) failed %s\n", s.name, err)
				// Assume error and bail
				done = true
				continue
			}
			s.log.Functionf("Creating %s at %s", "s.serveConnection", logutils.GetMyStack())
			go s.serveConnection(c, instance)
			instance++
		}
		s.log.Warnf("Start(%s) acceptor goroutine exiting", s.name)
	}(s)
	return nil
}

// Stop the publisher
func (s *Publisher) Stop() error {
	s.log.Functionf("Stop(%s)", s.name)
	if s.listener == nil {
		// Nothing to do
		return nil
	}
	close(s.doneChan)
	// Trigger any goroutine blocked in Accept to wake up and exit
	s.listener.Close()
	return nil
}

// Restart indicate that the topic is restarted if counter is non-zero
func (s *Publisher) Restart(restartCounter int) error {
	restartFile := s.dirName + "/" + "restarted"
	if restartCounter != 0 {
		str := strconv.Itoa(restartCounter)
		cb := []byte(str)
		err := fileutils.WriteRename(restartFile, cb)
		if err != nil {
			errStr := fmt.Sprintf("pub.restartImpl(%s): openfile failed %s", s.name, err)
			return errors.New(errStr)
		}
	} else {
		if err := os.Remove(restartFile); err != nil {
			errStr := fmt.Sprintf("pub.restartImpl(%s): remove failed %s", s.name, err)
			return errors.New(errStr)
		}
	}
	return nil
}

func (s *Publisher) serveConnection(conn net.Conn, instance int) {
	s.log.Functionf("serveConnection(%s/%d)\n", s.name, instance)
	defer conn.Close()
	s.stats.Connections.Add(1)
	defer s.stats.Connections.Add(-1)

	// Track the set of keys/values we are sending to the peer
	sendToPeer := make(pubsub.LocalCollection)
	sentRestartCounter := 0

	// Read request
	reader := NewFrameReader(conn)
	reader.alloc = &s.stats.AllocMessage
	frame, err := reader.ReadFrame()
	if err != nil {
		// Peer process could have died
		s.log.Errorf("serveConnection(%s/%d) error: %v", s.name, instance, err)
		return
	}

	request := strings.Split(string(frame), " ")
	s.stats.AllocMessage.Add(len(frame))
	s.stats.AllocMessage.Add(cap(request) * 16)
	reader.Release()
	s.log.Functionf("serveConnection read %d: %v\n", len(request), request)
	if len(request) != 2 || request[0] != "request" || request[1] != s.topic {
		s.log.Errorf("Invalid request message: %v\n", request)
		return
	}

	// Advertise our persistence so that the subscriber can detect a mismatch
	// between its Persistent option and ours. Older subscribers ignore the
	// extra field.
	hello := fmt.Sprintf("hello %s %t", s.topic, s.persistent)
	s.stats.AllocMessage.Add(len(hello))
	s.stats.AllocMessage.Add(len(hello))
	err = s.send(conn, []byte(hello), "")
	if err != nil {
		s.log.Errorf("serveConnection(%s/%d) failed %s\n", s.name, instance, err)
		return
	}
	// Insert our notification channel before we get the initial
	// snapshot to avoid missing any updates/deletes.
	updater := make(chan pubsub.Notify, 1)
	s.updaters.Add(s.log, updater, s.name, instance)
	defer s.updaters.Remove(s.log, updater)

	// Get a local snapshot of the collection and the set of keys
	// we need to send these. Updates the local collection.
	keys := s.differ.DetermineDiffs(sendToPeer)

	// Send the keys we just determined; all since this is the initial
	err = s.serialize(conn, keys, sendToPeer)
	if err != nil {
		s.log.Errorf("serveConnection(%s/%d) serialize failed %s\n", s.name, instance, err)
		return
	}
	err = s.sendComplete(conn)
	if err != nil {
		s.log.Errorf("serveConnection(%s/%d) sendComplete failed %s\n", s.name, instance, err)
		return
	}
	if s.restarted.RestartCounter() != sentRestartCounter {
		err = s.sendRestarted(conn, s.restarted.RestartCounter())
		if err != nil {
			s.log.Errorf("serveConnection(%s/%d) sendRestarted failed %s\n", s.name, instance, err)
			return
		}
		sentRestartCounter = s.restarted.RestartCounter()
	}

	// Handle any changes
	done := false
	for !done {
		s.log.Tracef("serveConnection(%s/%d) waiting for notification\n", s.name, instance)
		startWait := time.Now()
		select {
		case _, ok := <-s.doneChan:
			if !ok {
				done = true
				continue
			} else {
				s.log.Fatal("Received message on doneChan")
			}
		case <-updater:
		}
		waitTime := time.Since(startWait)
		s.log.Tracef("serveConnection(%s/%d) received notification waited %d seconds\n", s.name, instance, waitTime/time.Second)
		// Grab any change to restartCounter before we determine diffs
		newRestartCounter := s.restarted.RestartCounter()

		// Update and determine which keys changed
		keys := s.differ.DetermineDiffs(sendToPeer)

		// Send the updates and deletes for those keys
		err = s.serialize(conn, keys, sendToPeer)
		if err != nil {
			s.log.Errorf("serveConnection(%s/%d) serialize failed %s\n", s.name, instance, err)
			return
		}

		if newRestartCounter != sentRestartCounter {
			err = s.sendRestarted(conn, newRestartCounter)
			if err != nil {
				s.log.Errorf("serveConnection(%s/%d) sendRestarted failed %s\n", s.name, instance, err)
				return
			}
			sentRestartCounter = newRestartCounter
		}
	}
	s.log.Warnf("serveConnection(%s) goroutine exiting", s.name)
}

func (s *Publisher) serialize(sock net.Conn, keys []string,
	sendToPeer pubsub.LocalCollection) error {

	s.log.Tracef("serialize(%s, %v)\n", s.name, keys)

	for _, key := range keys {
		val, ok := sendToPeer[key]
		if ok {
			err := s.sendUpdate(sock, key, val)
			if err != nil {
				s.log.Errorf("serialize(%s) sendUpdate failed %s\n", s.name, err)
				return err
			}
		} else {
			err := s.sendDelete(sock, key)
			if err != nil {
				s.log.Errorf("serialize(%s) sendDelete failed %s\n", s.name, err)
				return err
			}
		}
	}
	return nil
}

func (s *Publisher) sendUpdate(sock net.Conn, key string,
	val []byte) error {

	s.log.Tracef("sendUpdate(%s): key %s\n", s.name, key)
	return s.send(sock, s.updateMessage(key, val), key)
}

// updateMessage returns "update topic key val" with key base64-encoded to
// avoid having spaces in it. val is sent as is; it is the last field, so it
// may contain spaces. The message is built in a single allocation since
// val can be large.
func (s *Publisher) updateMessage(key string, val []byte) []byte {
	n := s.updateMessageLen(key, val)
	s.stats.AllocMessage.Add(n)
	s.stats.AllocMessage.AddTemp(len(key))
	buf := make([]byte, 0, n)
	buf = append(buf, "update "...)
	buf = append(buf, s.topic...)
	buf = append(buf, ' ')
	buf = base64.StdEncoding.AppendEncode(buf, []byte(key))
	buf = append(buf, ' ')
	return append(buf, val...)
}

func (s *Publisher) updateMessageLen(key string, val []byte) int {
	return len("update ") + len(s.topic) + 1 +
		base64.StdEncoding.EncodedLen(len(key)) + 1 + len(val)
}

func (s *Publisher) sendDelete(sock net.Conn, key string) error {
	s.log.Tracef("sendDelete(%s): key %s\n", s.name, key)
	// base64-encode to avoid having spaces in the key
	sendKey := base64.StdEncoding.EncodeToString([]byte(key))
	buf := fmt.Sprintf("delete %s %s", s.topic, sendKey)
	s.stats.AllocMessage.AddTemp(len(key))
	s.stats.AllocMessage.Add(len(sendKey)) // EncodeToString: buffer
	s.stats.AllocMessage.Add(len(sendKey)) // and string
	s.stats.AllocMessage.Add(len(buf))
	s.stats.AllocMessage.Add(len(buf))
	return s.send(sock, []byte(buf), key)
}

func (s *Publisher) sendRestarted(sock net.Conn, restartCounter int) error {
	s.log.Functionf("sendRestarted(%s)\n", s.name)
	buf := fmt.Sprintf("restarted %s %d", s.topic, restartCounter)
	s.stats.AllocMessage.Add(len(buf))
	s.stats.AllocMessage.Add(len(buf))
	return s.send(sock, []byte(buf), "")
}

func (s *Publisher) sendComplete(sock net.Conn) error {
	s.log.Functionf("sendComplete(%s)\n", s.name)
	buf := fmt.Sprintf("complete %s", s.topic)
	s.stats.AllocMessage.Add(len(buf))
	s.stats.AllocMessage.Add(len(buf))
	return s.send(sock, []byte(buf), "")
}

// send writes msg as one frame, compressed if it is larger than maxsize. A
// message which does not fit even compressed is not sent: Publish refuses
// such values, so only a checkpoint written by another version of EVE can
// bring one here, and it must not make the publisher exit on every boot. A
// message larger than warnSize is logged whenever the publication reaches
// a new largest size.
func (s *Publisher) send(sock net.Conn, msg []byte, key string) error {
	size := int64(len(msg))
	s.stats.AddMessage(len(msg))
	if size > warnSize {
		s.stats.LargeWarnings.Add(1)
	}
	for size > warnSize {
		largest := s.largestSent.Load()
		if size <= largest {
			break
		}
		if s.largestSent.CompareAndSwap(largest, size) {
			s.log.Warnf("Large message (%d bytes, max %d uncompressed) sent to %s topic %s key %s",
				size, maxsize, s.name, s.topic, key)
			break
		}
	}
	if size <= maxsize {
		return writeFrame(sock, msg, false, &s.stats.AllocMessage)
	}
	frame, err := compress(msg)
	if err != nil {
		s.stats.Refused.Add(1)
		s.log.Errorf("Not sending to %s topic %s key %s: %v",
			s.name, s.topic, key, err)
		return nil
	}
	s.stats.AllocMessage.Add(cap(frame))
	s.stats.CompressedMessages.Add(1)
	s.stats.CompressedBytes.Add(int64(len(frame)))
	return writeFrame(sock, frame, true, &s.stats.AllocMessage)
}

// CheckMaxSize returns an error if the value does not fit in a message:
// one larger than maxsize must compress into maxsize bytes.
func (s *Publisher) CheckMaxSize(key string, val []byte) error {
	s.log.Tracef("CheckMaxSize(%s): key %s\n", s.name, key)
	if s.updateMessageLen(key, val) <= maxsize {
		return nil
	}
	frame, err := compress(s.updateMessage(key, val))
	if err != nil {
		return fmt.Errorf("key %s: %w", key, err)
	}
	s.stats.AllocMessage.Add(cap(frame))
	return nil
}
