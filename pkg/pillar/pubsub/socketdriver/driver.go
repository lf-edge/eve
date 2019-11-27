package socketdriver

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	log "github.com/sirupsen/logrus"
)

// Protocol over AF_UNIX or other IPC mechanism
// "request" from client after connect to sanity check subject.
// Server sends the other messages; "update" for initial values.
// "complete" once all initial keys/values in collection have been sent.
// "restarted" if/when pub.km.restarted is set.
// Ongoing we send "update" and "delete" messages.
// They keys and values are base64-encoded since they might contain spaces.
// We include typeName after command word for sanity checks.
// Hence the message format is
//	"request" topic
//	"hello"  topic
//	"update" topic key json-val
//	"delete" topic key
//	"complete" topic (aka synchronized)
//	"restarted" topic

// We always publish to our collection.
// We always write to a file in order to have a checkpoint on restart
// The special agent name "" implies always reading from the /var/run/zededa/
// directory.
const (
	publishToSock     = true  // XXX
	subscribeFromDir  = false // XXX
	subscribeFromSock = true  // XXX

	// For a subscription, if the agentName is empty we interpret that as
	// being directory in /var/tmp/zededa
	fixedName = "zededa"
	fixedDir  = "/var/tmp/" + fixedName
	maxsize   = 65535 // Max size for json which can be read or written

	// Copied from types package to avoid cycle in package dependencies
	// persistDir - Location to store persistent files.
	persistDir = "/persist"
	// persistConfigDir is where we keep some configuration across reboots
	persistConfigDir = persistDir + "/config"
)

/*
 Driver for pubsub using local unix-domain socket and files
*/
type SocketDriver struct {
}

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
		dirName = fmt.Sprintf("%s/%s", persistConfigDir, name)
	case persistent && !publishToDir:
		dirName = s.persistentDirName(name)
	case !persistent && publishToDir:
		// Special case for /var/tmp/zededa/
		dirName = s.fixedDirName(name)
	default:
		dirName = s.pubDirName(name)
	}

	if _, err := os.Stat(dirName); err != nil {
		log.Infof("Publish Create %s\n", dirName)
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
			log.Infof("Publish Create %s\n", dir)
			if err := os.MkdirAll(dir, 0700); err != nil {
				errStr := fmt.Sprintf("Publish(%s): %s",
					name, err)
				return nil, errors.New(errStr)
			}
		}
		if _, err := os.Stat(sockName); err == nil {
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
	return &SocketDriverPublish{
		sockName:       sockName,
		listener:       listener,
		dirName:        dirName,
		shouldPopulate: shouldPopulate,
		name:           name,
		topic:          topic,
		updaters:       updaterList,
		differ:         differ,
		restarted:      restarted,
	}, nil
}
func (s *SocketDriver) Subscriber(global bool, name, topic string, persistent bool, C chan pubsub.Change) (pubsub.DriverSubscriber, error) {
	var (
		sockName   = s.sockName(name)
		dirName    string
		subFromDir bool
	)

	// Special case for files in /var/tmp/zededa/ and also
	// for zedclient going away yet metrics being read after it
	// is gone.
	agentName := name
	if agentName == "" {
		subFromDir = true
		dirName = s.fixedDirName(name)
	} else if agentName == "zedclient" {
		subFromDir = true
		dirName = s.pubDirName(name)
	} else if persistent {
		subFromDir = true
		dirName = s.persistentDirName(name)
	} else {
		subFromDir = subscribeFromDir
		dirName = s.pubDirName(name)
	}
	return &SocketDriverSubscribe{
		subscribeFromDir: subFromDir,
		dirName:          dirName,
		name:             name,
		topic:            topic,
		sockName:         sockName,
		C:                C,
	}, nil
}

func (s *SocketDriver) sockName(name string) string {
	return fmt.Sprintf("/var/run/%s.sock", name)
}

func (s *SocketDriver) pubDirName(name string) string {
	return fmt.Sprintf("/var/run/%s", name)
}

func (s *SocketDriver) fixedDirName(name string) string {
	return fmt.Sprintf("%s/%s", fixedDir, name)
}

func (s *SocketDriver) persistentDirName(name string) string {
	return fmt.Sprintf("%s/status/%s", "/persist", name)
}
