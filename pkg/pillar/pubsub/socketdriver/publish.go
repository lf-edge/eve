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
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	log "github.com/sirupsen/logrus"
)

// Publisher implementation of `pubsub.DriverPublisher` for `SocketDriver`.
// Implements Unix-domain socket or directory publication,
// and directory-based persistence.
type Publisher struct {
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
}

// Publish publish a key-value pair
func (s *Publisher) Publish(key string, item []byte) error {
	fileName := s.dirName + "/" + key + ".json"
	log.Debugf("Publish writing %s\n", fileName)

	err := fileutils.WriteRename(fileName, item)
	if err != nil {
		return err
	}
	return nil
}

// Unpublish delete a key and publish its deletion
func (s *Publisher) Unpublish(key string) error {
	fileName := s.dirName + "/" + key + ".json"
	log.Debugf("Unpublish deleting file %s\n", fileName)
	if err := os.Remove(fileName); err != nil {
		return fmt.Errorf("Unpublish(%s/%s): failed %s", s.name, key, err)
	}
	return nil
}

// Load load entire persisted data set into a map
func (s *Publisher) Load() (map[string][]byte, bool, error) {
	dirName := s.dirName
	foundRestarted := false
	items := make(map[string][]byte)

	log.Debugf("Load(%s)\n", s.name)

	files, err := ioutil.ReadDir(dirName)
	if err != nil {
		// Drive on?
		log.Error(err)
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
			log.Errorf("populate: File disappeared <%s>\n",
				statusFile)
			continue
		}

		log.Debugf("Load found key %s file %s\n", key, statusFile)

		sb, err := ioutil.ReadFile(statusFile)
		if err != nil {
			log.Errorf("Load: %s for %s\n", err, statusFile)
			continue
		}
		items[key] = sb
	}
	return items, foundRestarted, err
}

// Start start publishing on the socket
func (s *Publisher) Start() error {
	// we only do this for not publishing to dir, and publishing to socket
	// which already was indicated by having the listener set up
	if s.listener == nil {
		return nil
	}
	go func(s *Publisher) {
		instance := 0
		for {
			c, err := s.listener.Accept()
			if err != nil {
				log.Errorf("publisher(%s) failed %s\n", s.name, err)
				continue
			}
			go s.serveConnection(c, instance)
			instance++
		}
	}(s)
	return nil
}

// Restart indicate that the topic is restarted, or clear it
func (s *Publisher) Restart(restarted bool) error {
	restartFile := s.dirName + "/" + "restarted"
	if restarted {
		f, err := os.OpenFile(restartFile, os.O_RDONLY|os.O_CREATE, 0600)
		if err != nil {
			errStr := fmt.Sprintf("pub.restartImpl(%s): openfile failed %s", s.name, err)
			return errors.New(errStr)
		}
		f.Close()
	} else {
		if err := os.Remove(restartFile); err != nil {
			errStr := fmt.Sprintf("pub.restartImpl(%s): remove failed %s", s.name, err)
			return errors.New(errStr)
		}
	}
	return nil
}

func (s *Publisher) serveConnection(conn net.Conn, instance int) {
	log.Infof("serveConnection(%s/%d)\n", s.name, instance)
	defer conn.Close()

	// Track the set of keys/values we are sending to the peer
	sendToPeer := make(pubsub.LocalCollection)
	sentRestarted := false
	// Read request
	buf := make([]byte, 65536)
	res, err := conn.Read(buf)
	if err != nil {
		// Peer process could have died
		log.Errorf("serveConnection(%s/%d) error: %v", s.name, instance, err)
		return
	}
	if res == len(buf) {
		// Likely truncated
		// Peer process could have died
		log.Errorf("serveConnection(%s/%d) request likely truncated\n", s.name, instance)
		return
	}

	request := strings.Split(string(buf[0:res]), " ")
	log.Infof("serveConnection read %d: %v\n", len(request), request)
	if len(request) != 2 || request[0] != "request" || request[1] != s.topic {
		log.Errorf("Invalid request message: %v\n", request)
		return
	}

	_, err = conn.Write([]byte(fmt.Sprintf("hello %s", s.topic)))
	if err != nil {
		log.Errorf("serveConnection(%s/%d) failed %s\n", s.name, instance, err)
		return
	}
	// Insert our notification channel before we get the initial
	// snapshot to avoid missing any updates/deletes.
	updater := make(chan pubsub.Notify, 1)
	s.updaters.Add(updater, s.name, instance)
	defer s.updaters.Remove(updater)

	// Get a local snapshot of the collection and the set of keys
	// we need to send these. Updates the local collection.
	keys := s.differ.DetermineDiffs(sendToPeer)

	// Send the keys we just determined; all since this is the initial
	err = s.serialize(conn, keys, sendToPeer)
	if err != nil {
		log.Errorf("serveConnection(%s/%d) serialize failed %s\n", s.name, instance, err)
		return
	}
	err = s.sendComplete(conn)
	if err != nil {
		log.Errorf("serveConnection(%s/%d) sendComplete failed %s\n", s.name, instance, err)
		return
	}
	if s.restarted.IsRestarted() && !sentRestarted {
		err = s.sendRestarted(conn)
		if err != nil {
			log.Errorf("serveConnection(%s/%d) sendRestarted failed %s\n", s.name, instance, err)
			return
		}
		sentRestarted = true
	}

	// Handle any changes
	for {
		log.Debugf("serveConnection(%s/%d) waiting for notification\n", s.name, instance)
		startWait := time.Now()
		<-updater
		waitTime := time.Since(startWait)
		log.Debugf("serveConnection(%s/%d) received notification waited %d seconds\n", s.name, instance, waitTime/time.Second)

		// Update and determine which keys changed
		keys := s.differ.DetermineDiffs(sendToPeer)

		// Send the updates and deletes for those keys
		err = s.serialize(conn, keys, sendToPeer)
		if err != nil {
			log.Errorf("serveConnection(%s/%d) serialize failed %s\n", s.name, instance, err)
			return
		}

		if s.restarted.IsRestarted() && !sentRestarted {
			err = s.sendRestarted(conn)
			if err != nil {
				log.Errorf("serveConnection(%s/%d) sendRestarted failed %s\n", s.name, instance, err)
				return
			}
			sentRestarted = true
		}
	}
}

func (s *Publisher) serialize(sock net.Conn, keys []string,
	sendToPeer pubsub.LocalCollection) error {

	log.Debugf("serialize(%s, %v)\n", s.name, keys)

	for _, key := range keys {
		val, ok := sendToPeer[key]
		if ok {
			err := s.sendUpdate(sock, key, val)
			if err != nil {
				log.Errorf("serialize(%s) sendUpdate failed %s\n", s.name, err)
				return err
			}
		} else {
			err := s.sendDelete(sock, key)
			if err != nil {
				log.Errorf("serialize(%s) sendDelete failed %s\n", s.name, err)
				return err
			}
		}
	}
	return nil
}

func (s *Publisher) sendUpdate(sock net.Conn, key string,
	val []byte) error {

	log.Debugf("sendUpdate(%s): key %s\n", s.name, key)
	// base64-encode to avoid having spaces in the key and val
	sendKey := base64.StdEncoding.EncodeToString([]byte(key))
	sendVal := base64.StdEncoding.EncodeToString(val)
	buf := fmt.Sprintf("update %s %s %s", s.topic, sendKey, sendVal)
	if len(buf) >= maxsize {
		log.Fatalf("Too large message (%d bytes) sent to %s topic %s key %s",
			len(buf), s.name, s.topic, key)
	}
	_, err := sock.Write([]byte(buf))
	return err
}

func (s *Publisher) sendDelete(sock net.Conn, key string) error {
	log.Debugf("sendDelete(%s): key %s\n", s.name, key)
	// base64-encode to avoid having spaces in the key
	sendKey := base64.StdEncoding.EncodeToString([]byte(key))
	buf := fmt.Sprintf("delete %s %s", s.topic, sendKey)
	if len(buf) >= maxsize {
		log.Fatalf("Too large message (%d bytes) sent to %s topic %s key %s",
			len(buf), s.name, s.topic, key)
	}
	_, err := sock.Write([]byte(buf))
	return err
}

func (s *Publisher) sendRestarted(sock net.Conn) error {
	log.Infof("sendRestarted(%s)\n", s.name)
	buf := fmt.Sprintf("restarted %s", s.topic)
	if len(buf) >= maxsize {
		log.Fatalf("Too large message (%d bytes) sent to %s topic %s",
			len(buf), s.name, s.topic)
	}
	_, err := sock.Write([]byte(buf))
	return err
}

func (s *Publisher) sendComplete(sock net.Conn) error {
	log.Infof("sendComplete(%s)\n", s.name)
	buf := fmt.Sprintf("complete %s", s.topic)
	if len(buf) >= maxsize {
		log.Fatalf("Too large message (%d bytes) sent to %s topic %s",
			len(buf), s.name, s.topic)
	}
	_, err := sock.Write([]byte(buf))
	return err
}
