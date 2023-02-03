// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const multiInstStatsEPString = "localhost:8234"

var (
	evInstStats    [types.EdgeviewMaxInstNum]evLocalStats // instances stats
	edgeviewInstID int                                    // if set, range 1 to 5
)

type evLocalStats struct {
	InstID int                  `json:"instID"`
	Stats  types.EdgeviewStatus `json:"stats"`
}

func serverEvStats() {
	http.HandleFunc("/evStats", evStatsHandler)
	err := http.ListenAndServe(multiInstStatsEPString, nil)
	if err != nil {
		log.Errorf("serverEvStats: exit with error: %v", err)
	}
}

func doInfoPub(infoPub pubsub.Publication) {
	if infoPub != nil {
		if edgeviewInstID == 0 {
			err := infoPub.Publish("global", evStatus)
			if err != nil {
				log.Noticef("evinfopub: publish error: %v\n", err)
			}
		} else if edgeviewInstID == 1 {
			evInstStats[0].Stats = evStatus
			for i, s := range evInstStats {
				if i == 0 {
					continue
				}
				evInstStats[0].Stats.CmdCountDev += s.Stats.CmdCountDev
				evInstStats[0].Stats.CmdCountApp += s.Stats.CmdCountApp
				evInstStats[0].Stats.CmdCountExt += s.Stats.CmdCountExt
			}
			err := infoPub.Publish("global", evInstStats[0].Stats)
			if err != nil {
				log.Errorf("evinfopub: publish error: %v\n", err)
			}
		}
	} else if edgeviewInstID > 1 {
		reportInstStats()
	}
}

// in multiple instance case, inst-1 process will be the server to
// receive other instances status update.
func evStatsHandler(w http.ResponseWriter, r *http.Request) {
	log.Noticef("InstStats: stats server get message")

	switch r.Method {
	case "POST":
		var localStats evLocalStats
		content, err := io.ReadAll(r.Body)
		if err != nil {
			log.Errorf("stats server read error: %v", err)
			return
		}
		err = json.Unmarshal(content, &localStats)
		if err != nil {
			log.Errorf("stats server unmarshal error: %v", err)
			return
		}

		if localStats.InstID < 2 || localStats.InstID > types.EdgeviewMaxInstNum {
			log.Errorf("stats server receive incorrect stats: %v", localStats)
			return
		}
		evInstStats[localStats.InstID-1] = localStats
		log.Tracef("InstStats: received stats from inst %d ok, %v", localStats.InstID, localStats) // XXX

		trigPubchan <- true
	default:
	}
}

func reportInstStats() {
	var localStats evLocalStats
	localStats.InstID = edgeviewInstID
	localStats.Stats = evStatus

	jmsg, err := json.Marshal(localStats)
	if err != nil {
		log.Errorf("stats client marshal error: %v", err)
		return
	}

	_, err = http.Post("http://"+multiInstStatsEPString+"/evStats", "application/json", bytes.NewBuffer(jmsg))
	if err != nil {
		log.Errorf("InstStats: stats client http post error: %v", err)
		return
	}
	log.Tracef("InstStats: inst %d, posted ok", edgeviewInstID)
}
