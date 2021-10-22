// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package socketdriver

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/sirupsen/logrus"
)

// Protocol over AF_UNIX or other IPC mechanism
// "request" from client after connect to sanity check subject.
// Server sends the other messages; "update" for initial values.
// "complete" once all initial keys/values in collection have been sent.
// "restarted" if/when pub.km.restartCounter is set.
// Ongoing we send "update" and "delete" messages.
// They keys and values are base64-encoded since they might contain spaces.
// We include typeName after command word for sanity checks.
// Hence the message format is
//	"request" topic
//	"hello"  topic
//	"update" topic key json-val
//	"delete" topic key
//	"complete" topic (aka synchronized)
//	"restarted" topic count

// We always publish to our collection.
// We always write to a file in order to have a checkpoint on restart
// The special agent name "" implies always reading from the /run/global/
// directory.
const (
	publishToSock     = true  // XXX
	subscribeFromDir  = false // XXX
	subscribeFromSock = true  // XXX

	// For a subscription, if the agentName is empty we interpret that as
	// being directory in /run/global
	fixedName = "global"
	fixedDir  = "/run/" + fixedName
	maxsize   = 65535 // Max size for json which can be read or written

	// Copied from types package to avoid cycle in package dependencies
	// persistDir - Location to store persistent files.
	persistDir = "/persist"
	// persistConfigDir is where we keep some configuration across reboots
	persistConfigDir = persistDir + "/config"
)

// SocketDriver driver for pubsub using local unix-domain socket and files
type SocketDriver struct {
	Logger  *logrus.Logger
	Log     *base.LogObject
	RootDir string // Default is "/"; tests can override
}

// Publisher return an implementation of `pubsub.DriverPublisher` for
// `SocketDriver`
func (s *SocketDriver) Publisher(global bool, name, topic string, persistent bool, updaterList *pubsub.Updaters, restarted pubsub.Restarted, differ pubsub.Differ) (pubsub.DriverPublisher, error) {
	var (
		dirName, sockName string
		publishToDir      bool
		listener          net.Listener
		err               error
	)
	shouldPopulate := false

	// We always write to the directory as a checkpoint for process restart
	// That directory could be persistent in which case it will survive
	// a reboot.

	// if the agentName is "", signal that we publish to dir, rather than
	// to sock
	if global {
		publishToDir = true
	}

	// the dirName depends on if we are persistent, and if it is the global config
	switch {
	case persistent && publishToDir:
		// Special case for /persist/config/
		dirName = fmt.Sprintf("%s/%s/%s", s.RootDir, persistConfigDir, name)
	case persistent && !publishToDir:
		dirName = s.persistentDirName(name)
	case !persistent && publishToDir:
		// Special case for /run/global
		dirName = s.fixedDirName(name)
	default:
		dirName = s.pubDirName(name)
	}

	if _, err := os.Stat(dirName); err != nil {
		s.Log.Functionf("Publish Create %s\n", dirName)
		if err := os.MkdirAll(dirName, 0700); err != nil {
			errStr := fmt.Sprintf("Publish(%s): %s",
				name, err)
			return nil, errors.New(errStr)
		}
	} else {
		// Read existing status from dir
		shouldPopulate = true
	}

	if !publishToDir && publishToSock {
		sockName = s.sockName(name)
		dir := path.Dir(sockName)
		if _, err := os.Stat(dir); err != nil {
			s.Log.Functionf("Publish Create %s\n", dir)
			if err := os.MkdirAll(dir, 0700); err != nil {
				errStr := fmt.Sprintf("Publish(%s): %s",
					name, err)
				return nil, errors.New(errStr)
			}
		}
		if _, err := os.Stat(sockName); err == nil {
			// This could either be a left-over in the filesystem
			// or some other process (or ourselves) using the same
			// name to publish. Try connect to see if it is the latter.
			sock, err := net.Dial("unixpacket", sockName)
			if err == nil {
				sock.Close()
				s.Log.Fatalf("Can not publish %s since it it already used",
					sockName)
			}
			if err := os.Remove(sockName); err != nil {
				errStr := fmt.Sprintf("Publish(%s): %s",
					name, err)
				return nil, errors.New(errStr)
			}
		}
		listener, err = net.Listen("unixpacket", sockName)
		if err != nil {
			errStr := fmt.Sprintf("Publish(%s): failed %s",
				name, err)
			return nil, errors.New(errStr)
		}
	}
	doneChan := make(chan struct{})
	return &Publisher{
		sockName:       sockName,
		listener:       listener,
		dirName:        dirName,
		shouldPopulate: shouldPopulate,
		name:           name,
		topic:          topic,
		updaters:       updaterList,
		differ:         differ,
		restarted:      restarted,
		logger:         s.Logger,
		log:            s.Log,
		doneChan:       doneChan,
		rootDir:        s.RootDir,
	}, nil
}

// Subscriber return an implementation of `pubsub.DriverSubscriber` for
// `SocketDriver`
func (s *SocketDriver) Subscriber(global bool, name, topic string, persistent bool, C chan pubsub.Change) (pubsub.DriverSubscriber, error) {
	var (
		sockName   = s.sockName(name)
		dirName    string
		subFromDir bool
	)

	// Special case for files in /run/global/ and also
	// for zedclient going away yet metrics being read after it
	// is gone.
	var agentName string
	names := strings.Split(name, "/")
	if len(names) > 0 {
		agentName = names[0]
	}

	if global {
		subFromDir = true
		if persistent {
			// Special case for /persist/config/
			dirName = fmt.Sprintf("%s/%s/%s", s.RootDir,
				persistConfigDir, name)
		} else {
			dirName = s.fixedDirName(name)
		}
	} else if agentName == "zedclient" {
		subFromDir = true
		if persistent {
			dirName = s.persistentDirName(name)
		} else {
			dirName = s.pubDirName(name)
		}
	} else if persistent {
		// We do the initial Load from the directory if it
		// exists, but subsequent updates come over IPC
		subFromDir = false
		dirName = s.persistentDirName(name)
	} else {
		subFromDir = subscribeFromDir
		dirName = s.pubDirName(name)
	}
	doneChan := make(chan struct{})
	return &Subscriber{
		subscribeFromDir: subFromDir,
		dirName:          dirName,
		name:             name,
		topic:            topic,
		sockName:         sockName,
		C:                C,
		logger:           s.Logger,
		log:              s.Log,
		doneChan:         doneChan,
		rootDir:          s.RootDir,
	}, nil
}

// DefaultName default name for an agent when none is provided
func (s *SocketDriver) DefaultName() string {
	return fixedName
}

func (s *SocketDriver) sockName(name string) string {
	return fmt.Sprintf("%s/var/run/%s.sock", s.RootDir, name)
}

func (s *SocketDriver) pubDirName(name string) string {
	return fmt.Sprintf("%s/var/run/%s", s.RootDir, name)
}

func (s *SocketDriver) fixedDirName(name string) string {
	return fmt.Sprintf("%s/%s/%s", s.RootDir, fixedDir, name)
}

func (s *SocketDriver) persistentDirName(name string) string {
	return fmt.Sprintf("%s/%s/status/%s", s.RootDir, "/persist", name)
}

// Use a buffer pool to minimize memory usage
var bufPool = &sync.Pool{
	New: func() interface{} {
		buffer := make([]byte, maxsize+1)
		return buffer
	},
}

// Track allocations for debug
var allocated uint32

// GetBuffer returns a buffer and a done func to call at defer.
func GetBuffer() ([]byte, func()) {
	buf := bufPool.Get().([]byte)
	atomic.AddUint32(&allocated, 1)
	return buf, func() {
		bufPool.Put(buf)
		atomic.AddUint32(&allocated, ^uint32(0))
	}
}

// logs a message if the allocation changed
var lastLoggedAllocated uint32

func maybeLogAllocated(log *base.LogObject) {
	if lastLoggedAllocated == allocated {
		return
	}
	log.Functionf("pubsub buffer allocation changed from %d to  %d",
		lastLoggedAllocated, allocated)
	lastLoggedAllocated = allocated
}

// Poll to check if we should go away
func areWeDone(log *base.LogObject, doneChan <-chan struct{}) bool {
	select {
	case _, ok := <-doneChan:
		if !ok {
			return true
		} else {
			log.Fatal("Received message on doneChan")
		}
	default:
	}
	return false
}
