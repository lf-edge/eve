// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package reverse provide a limited variant of pubsub where the subscriber
// creates the listener and the publisher connects. Used when the publisher
// is not a long-running agent, and there is only one subscriber.
package reverse

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

// Publish publishes data to
func Publish(log *base.LogObject, agent string, data interface{}) error {
	log.Functionf("publish(%s)", agent)
	sockName := getSocketName(agent, data)

	if _, err := os.Stat(sockName); err != nil {
		err := fmt.Errorf("publish(%s): exception while check socket. %s", sockName, err.Error())
		log.Error(err.Error())
		return err
	}

	byteData, err := json.Marshal(data)
	if err != nil {
		err := fmt.Errorf("publish(%s): exception while marshalling data. %s",
			sockName, err.Error())
		log.Error(err.Error())
		return err
	}

	conn, err := net.Dial("unixpacket", sockName)
	if err != nil {
		err := fmt.Errorf("publish(%s): exception while dialing socket. %s",
			sockName, err.Error())
		log.Error(err.Error())
		return err
	}
	defer conn.Close()

	if _, err := conn.Write(byteData); err != nil {
		err := fmt.Errorf("publish(%s): exception while writing data to the socket. %s",
			sockName, err.Error())
		log.Error(err.Error())
		return err
	}
	return nil
}

func getSocketName(agent string, topic interface{}) string {
	return path.Join("/var/run", agent,
		fmt.Sprintf("%s.sock", pubsub.TypeToName(topic)))
}
