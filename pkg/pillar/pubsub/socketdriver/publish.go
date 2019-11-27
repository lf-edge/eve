package socketdriver

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	log "github.com/sirupsen/logrus"
)

type SocketDriverPublish struct {
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

func (s *SocketDriverPublish) Publish(key string, item interface{}) error {
	fileName := s.dirName + "/" + key + ".json"
	log.Debugf("Publish writing %s\n", fileName)

	// XXX already did a marshal in deepCopy; save that result?
	b, err := json.Marshal(item)
	if err != nil {
		log.Fatal("json Marshal in Publish", err)
	}
	err = s.writeRename(fileName, b)
	if err != nil {
		return err
	}
	return nil
}

func (s *SocketDriverPublish) Unpublish(key string) error {
	fileName := s.dirName + "/" + key + ".json"
	log.Debugf("Unpublish deleting file %s\n", fileName)
	if err := os.Remove(fileName); err != nil {
		return fmt.Errorf("Unpublish(%s/%s): failed %s", s.name, key, err)
	}
	return nil
}

func (s *SocketDriverPublish) Load() (map[string]interface{}, bool, error) {
	dirName := s.dirName
	foundRestarted := false
	items := make(map[string]interface{})

	log.Infof("Load(%s)\n", s.name)

	files, err := ioutil.ReadDir(dirName)
	if err != nil {
		log.Fatal(err)
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

		log.Infof("populate found key %s file %s\n", key, statusFile)

		sb, err := ioutil.ReadFile(statusFile)
		if err != nil {
			log.Errorf("populate: %s for %s\n", err, statusFile)
			continue
		}
		var item interface{}
		if err := json.Unmarshal(sb, &item); err != nil {
			log.Errorf("populate: %s file: %s\n",
				err, statusFile)
			continue
		}
		items[key] = item
	}
	return items, foundRestarted, err
}

func (s *SocketDriverPublish) Start() error {
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
}

func (s *SocketDriverPublish) Restart(restarted bool) error {
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

func (s *SocketDriverPublish) serveConnection(conn net.Conn, instance int) {
	log.Infof("serveConnection(%s/%d)\n", s.name, instance)
	defer conn.Close()

	// Track the set of keys/values we are sending to the peer
	sendToPeer := make(pubsub.LocalCollection)
	sentRestarted := false
	// Read request
	buf := make([]byte, 65536)
	res, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("serveConnection(%s/%d) error: %v", s.name, instance, err)
	}
	if res == len(buf) {
		// Likely truncated
		log.Fatalf("serveConnection(%s/%d) request likely truncated\n", s.name, instance)
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
	// we need to send these. Updates the slave collection.
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

func (s *SocketDriverPublish) serialize(sock net.Conn, keys []string,
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

func (s *SocketDriverPublish) sendUpdate(sock net.Conn, key string,
	val interface{}) error {

	log.Debugf("sendUpdate(%s): key %s\n", s.name, key)
	b, err := json.Marshal(val)
	if err != nil {
		log.Fatal("json Marshal in sendUpdate", err)
	}
	// base64-encode to avoid having spaces in the key and val
	sendKey := base64.StdEncoding.EncodeToString([]byte(key))
	sendVal := base64.StdEncoding.EncodeToString(b)
	buf := fmt.Sprintf("update %s %s %s", s.topic, sendKey, sendVal)
	if len(buf) >= maxsize {
		log.Fatalf("Too large message (%d bytes) sent to %s topic %s key %s",
			len(buf), s.name, s.topic, key)
	}
	_, err = sock.Write([]byte(buf))
	return err
}

func (s *SocketDriverPublish) sendDelete(sock net.Conn, key string) error {
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

func (s *SocketDriverPublish) sendRestarted(sock net.Conn) error {
	log.Infof("sendRestarted(%s)\n", s.name)
	buf := fmt.Sprintf("restarted %s", s.topic)
	if len(buf) >= maxsize {
		log.Fatalf("Too large message (%d bytes) sent to %s topic %s",
			len(buf), s.name, s.topic)
	}
	_, err := sock.Write([]byte(buf))
	return err
}

func (s *SocketDriverPublish) sendComplete(sock net.Conn) error {
	log.Infof("sendComplete(%s)\n", s.name)
	buf := fmt.Sprintf("complete %s", s.topic)
	if len(buf) >= maxsize {
		log.Fatalf("Too large message (%d bytes) sent to %s topic %s",
			len(buf), s.name, s.topic)
	}
	_, err := sock.Write([]byte(buf))
	return err
}

// writeRename write data to a fmpfile and then rename it to a desired name
func (s *SocketDriverPublish) writeRename(fileName string, b []byte) error {
	dirName := filepath.Dir(fileName)
	// Do atomic rename to avoid partially written files
	tmpfile, err := ioutil.TempFile(dirName, "pubsub")
	if err != nil {
		errStr := fmt.Sprintf("writeRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}
	defer tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	_, err = tmpfile.Write(b)
	if err != nil {
		errStr := fmt.Sprintf("writeRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}
	if err := tmpfile.Close(); err != nil {
		errStr := fmt.Sprintf("writeRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}
	if err := os.Rename(tmpfile.Name(), fileName); err != nil {
		errStr := fmt.Sprintf("writeRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}
	return nil
}
