// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path"
	"time"

	chrony "github.com/facebook/time/ntp/chrony"
	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"google.golang.org/protobuf/proto"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// Path to unix chrony socket
	unixChronydPath = "/run/chrony/chronyd.sock"
)

var prevInfoNTPSourcesMap map[destinationBitset]*info.ZInfoNTPSources

func getForceSendInterval(ctx *zedagentContext) time.Duration {
	interval := ctx.globalConfig.GlobalValueInt(types.NTPSourcesInterval)
	return time.Duration(interval) * time.Second
}

// Run a periodic post of the NTP sources information.
func ntpSourcesTimerTask(ctx *zedagentContext, handleChannel chan interface{},
	triggerNTPSourcesInfo chan destinationBitset) {

	prevInfoNTPSourcesMap = make(map[destinationBitset]*info.ZInfoNTPSources)

	// Ticker for periodic publishing NTP sources to the controller.
	// The period is rather small, because NTP sources are published
	// if something was really changed. See the @publishNTPSourcesToDest
	ticker := time.NewTicker(10 * time.Second)

	// Return handles to the caller.
	handleChannel <- ticker

	wdName := agentName + "-ntp"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ctx.ps.StillRunning(wdName, warningTime, errorTime)
	ctx.ps.RegisterFileWatchdog(wdName)

	ts := time.Now()
	for {
		select {
		case <-ticker.C:
			dest := ControllerDest
			if time.Now().Sub(ts) > getForceSendInterval(ctx) {
				// Periodically do a force send to be sure
				// controller gets an NTP update in any case
				dest |= ForceSend
				ts = time.Now()
			}
			publishNTPSources(ctx, wdName, dest)
		case dest := <-triggerNTPSourcesInfo:
			publishNTPSources(ctx, wdName, dest)
		case <-stillRunning.C:
		}
		ctx.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

func publishNTPSources(ctx *zedagentContext, wdName string,
	dest destinationBitset) {
	info := getNTPSourcesInfo(ctx)
	if info == nil {
		// Not available.
		return
	}
	start := time.Now()
	publishNTPSourcesToDest(ctx, info, dest)
	ctx.ps.CheckMaxTimeTopic(wdName, "publishNTPSources", start,
		warningTime, errorTime)
}

func ntpSourcesChanged(info *info.ZInfoNTPSources,
	dest destinationBitset) bool {

	onlydest := (dest & AllDest)
	prev, cached := prevInfoNTPSourcesMap[onlydest]
	prevInfoNTPSourcesMap[onlydest] = info
	if !cached {
		// First time
		return true
	}
	if len(prev.Sources) != len(info.Sources) {
		// Set of sources has been changed
		return true
	}
	for i, source := range info.Sources {
		prevSource := prev.Sources[i]
		if prevSource.State != source.State ||
			prevSource.Mode != source.Mode ||
			prevSource.Reachable != source.Reachable {
			// Some fields have been changed
			return true
		}
	}
	// Same
	return false
}

func publishNTPSourcesToDest(ctx *zedagentContext,
	infoNTPSources *info.ZInfoNTPSources, dest destinationBitset) {

	if dest == 0 {
		log.Errorf("publishNTPSourcesToDest: incorrect destination")
		return
	}
	if (dest &^ LPSDest) == 0 {
		// TODO: we don't support LPS
		return
	}
	changed := ntpSourcesChanged(infoNTPSources, dest)
	if !changed && (dest&ForceSend) == 0 {
		// Nothing was changed and force send is not requested,
		// so just return
		return
	}
	infoMsg := &info.ZInfoMsg{
		Ztype: info.ZInfoTypes_ZiNTPSources,
		DevId: devUUID.String(),
		InfoContent: &info.ZInfoMsg_NtpSources{
			NtpSources: infoNTPSources,
		},
		AtTimeStamp: timestamppb.Now(),
	}

	log.Functionf("publishNTPSourcesToDest: sending %v", infoMsg)
	data, err := proto.Marshal(infoMsg)
	if err != nil {
		log.Fatal("publishNTPSourcesToController: proto marshaling error: ", err)
	}
	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("malloc error")
	}

	const bailOnHTTPErr = false
	const withNetTrace = false
	key := "ntpsources:" + devUUID.String()

	// Although NTP update have periodic nature we really care that
	// all updates should be delivered to the controller, so clear
	// @forcePeriodic.
	forcePeriodic := false
	queueInfoToDest(ctx, dest, key, buf, bailOnHTTPErr, withNetTrace,
		forcePeriodic, info.ZInfoTypes_ZiNTPSources)
}

// createNTPSource() returns `info.NTPSource`. The code is based on the
// https://github.com/facebook/time/blob/main/cmd/ntpcheck/checker
func createNTPSource(s *chrony.ReplySourceData,
	p *chrony.ReplyNTPData,
	n *chrony.ReplyNTPSourceName) (*info.NTPSource, error) {

	// Clear auth and interleaved flag
	flash := s.Flags & chrony.NTPFlagsTests
	// Don't report all flashers if peer is unreachable
	if flash > 0 {
		flash ^= chrony.NTPFlagsTests
	}
	ntpSource := info.NTPSource{
		Authenticated: (s.Flags & chrony.NTPFlagAuthenticated) != 0,
		Reachable:     s.Reachability == 255, // all 8 attempts
		Reachability:  uint32(s.Reachability),
		// We have to advance on 1 due to the UNSPECIFIED enum in protobuf
		Mode: info.NTPSourceMode(s.Mode + 1),
		// We have to advance on 1 due to the UNSPECIFIED enum in protobuf
		State: info.NTPSourceState(s.State + 1),
		Flags: uint32(flash),
		// sourceData offset and NTPData offset sign has opposite meaning
		Offset:  -1 * s.OrigLatestMeas,
		Poll:    int32(s.Poll),
		Stratum: uint32(s.Stratum),
		// Address of the NTP peer, so destination
		DstAddr: s.IPAddr.String(),
	}
	if ntpSource.Mode > info.NTPSourceMode_NTP_SOURCE_MODE_REF {
		ntpSource.Mode = info.NTPSourceMode_NTP_SOURCE_MODE_UNSPECIFIED
	}
	if ntpSource.State > info.NTPSourceState_NTP_SOURCE_STATE_OUTLIER {
		ntpSource.State = info.NTPSourceState_NTP_SOURCE_STATE_UNSPECIFIED
	}

	// Populate data from NTPData struct
	if p != nil {
		refID := chrony.RefidAsHEX(p.RefID)
		// Only stratum 1 servers can have GPS or something else as string refID
		if p.Stratum == 1 {
			refIDStr := chrony.RefidToString(p.RefID)
			if len(refIDStr) > 0 {
				refID = refIDStr
			}
		}
		ntpSource.Leap = uint32(p.Leap)
		ntpSource.Poll = int32(p.Poll)
		// Local address the connection to NTP peer, so source
		ntpSource.SrcAddr = p.LocalAddr.String()
		ntpSource.RefTime = timestamppb.New(p.RefTime)
		ntpSource.Offset = p.Offset
		ntpSource.Dispersion = p.PeerDispersion
		// Missing that info
		ntpSource.SrcPort = 0
		ntpSource.DstPort = uint32(p.RemotePort)
		ntpSource.RefId = refID
		ntpSource.Jitter = p.PeerDispersion
		ntpSource.RootDelay = p.RootDelay
		ntpSource.Precision = uint32(p.Precision)
		ntpSource.Delay = p.PeerDelay
		ntpSource.RootDisp = p.RootDispersion
	}
	if n != nil {
		// This field is zero padded in chrony, so we need to trim it
		ntpSource.Hostname = string(bytes.TrimRight(n.Name[:], "\x00"))
	}

	return &ntpSource, nil
}

type chronyConn struct {
	net.Conn
	local string
}

// dialUnixWithChronyd() established connection. The code is a based on the
// https://github.com/facebook/time/blob/main/cmd/ntpcheck/checker
func dialUnixWithChronyd(address string) (*chronyConn, error) {
	base, _ := path.Split(address)
	local := path.Join(base, fmt.Sprintf("chronyc.%d.sock", os.Getpid()))
	conn, err := net.DialUnix("unixgram",
		&net.UnixAddr{Name: local, Net: "unixgram"},
		&net.UnixAddr{Name: address, Net: "unixgram"},
	)
	if err != nil {
		// Even there was an error, net.DialUnix() leaves trash behind.
		// What a shame.
		os.Remove(local)
		return nil, err
	}
	if err := os.Chmod(local, 0600); err != nil {
		conn.Close()
		os.Remove(local)
		return nil, err
	}
	return &chronyConn{Conn: conn, local: local}, nil
}

// getNTPSourcesInfo() returns `info.ZInfoNTPSources`. The code is based on the
// https://github.com/facebook/time/blob/main/cmd/ntpcheck/checker
func getNTPSourcesInfo(ctx *zedagentContext) *info.ZInfoNTPSources {
	conn, err := dialUnixWithChronyd(unixChronydPath)
	if err != nil {
		log.Errorf("getNTPSourcesInfo: can't connect to chronyd: %v", err)
		return nil
	}
	defer func() {
		conn.Close()
		os.Remove(conn.local)
	}()

	client := chrony.Client{Sequence: 1, Connection: conn}
	sourcesReq := chrony.NewSourcesPacket()
	packet, err := client.Communicate(sourcesReq)
	if err != nil {
		log.Errorf("getNTPSourcesInfo: failed to get 'sources' response: %v", err)
		return nil
	}
	sources, ok := packet.(*chrony.ReplySources)
	if !ok {
		log.Errorf("getNTPSourcesInfo: failed to convert to reply: %v", err)
		return nil
	}

	info := info.ZInfoNTPSources{}

	for i := 0; i < sources.NSources; i++ {
		sourceDataReq := chrony.NewSourceDataPacket(int32(i))
		packet, err = client.Communicate(sourceDataReq)
		if err != nil {
			log.Errorf("getNTPSourcesInfo: failed to get 'sourcedata' response for source #%d, err %v", i, err)
			return nil
		}
		sourceData, ok := packet.(*chrony.ReplySourceData)
		if !ok {
			log.Errorf("getNTPSourcesInfo: got wrong 'sourcedata' response %+v", packet)
			return nil
		}

		// get ntpdata when using a unix socket
		var ntpData *chrony.ReplyNTPData
		if sourceData.Mode != chrony.SourceModeRef {
			ntpDataReq := chrony.NewNTPDataPacket(sourceData.IPAddr)
			packet, err = client.Communicate(ntpDataReq)
			if err != nil {
				log.Errorf("getNTPSourcesInfo: failed to get 'ntpdata' response for source #%d", i)
				return nil
			}
			ntpData, ok = packet.(*chrony.ReplyNTPData)
			if !ok {
				log.Errorf("getNTPSourcesInfo: got wrong 'ntpdata' response %+v", packet)
				return nil
			}
		}
		var ntpSourceName *chrony.ReplyNTPSourceName
		if sourceData.Mode != chrony.SourceModeRef {
			ntpSourceNameReq := chrony.NewNTPSourceNamePacket(sourceData.IPAddr)
			packet, err = client.Communicate(ntpSourceNameReq)
			if err != nil {
				log.Errorf("getNTPSourcesInfo: failed to get 'sourcename' response for source #%d", i)
				return nil
			}
			ntpSourceName, ok = packet.(*chrony.ReplyNTPSourceName)
			if !ok {
				log.Errorf("getNTPSourcesInfo: got wrong 'sourcename' response %+v", packet)
				return nil
			}
		}
		ntpSource, err := createNTPSource(sourceData, ntpData, ntpSourceName)
		if err != nil {
			log.Errorf("getNTPSourcesInfo: failed to create Peer structure from response packet for peer=%s", sourceData.IPAddr)
			return nil
		}
		info.Sources = append(info.Sources, ntpSource)
	}

	return &info
}
