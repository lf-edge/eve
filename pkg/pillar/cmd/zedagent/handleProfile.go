// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/profile"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
)

const (
	defaultLocalProfileServerPort = "8888"
	savedLocalProfileFile         = "lastlocalprofile"
)

// urlAndSrcIP structure for mapping source IP and url of local server
type urlAndSrcIP struct {
	srcIP     net.IP
	actualURL string
}

func getLocalProfileURL(localProfileServer string) (string, error) {
	localProfileURL := fmt.Sprintf("http://%s", localProfileServer)
	u, err := url.Parse(localProfileURL)
	if err != nil {
		return "", fmt.Errorf("url.Parse: %s", err)
	}
	if u.Port() == "" {
		localProfileURL = fmt.Sprintf("%s:%s", localProfileURL, defaultLocalProfileServerPort)
	}
	return fmt.Sprintf("%s/api/v1/local_profile", localProfileURL), nil
}

// Run a periodic fetch of the currentProfile from localServer
func localProfileTimerTask(handleChannel chan interface{}, getconfigCtx *getconfigContext) {

	ctx := getconfigCtx.zedagentCtx

	// use ConfigInterval as localProfileInterval
	localProfileInterval := ctx.globalConfig.GlobalValueInt(types.ConfigInterval)
	interval := time.Duration(localProfileInterval) * time.Second
	max := float64(interval)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))
	// Return handle to caller
	handleChannel <- ticker

	log.Functionf("localProfileTimerTask: waiting for localProfileTrigger")
	//wait for the first trigger comes from parseProfile to have information about localProfileServer
	<-getconfigCtx.localProfileTrigger
	log.Functionf("localProfileTimerTask: waiting for localProfileTrigger done")
	//trigger again to pass into loop
	triggerGetLocalProfile(getconfigCtx)

	wdName := agentName + "currentProfile"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ctx.ps.StillRunning(wdName, warningTime, errorTime)
	ctx.ps.RegisterFileWatchdog(wdName)

	for {
		select {
		case <-getconfigCtx.localProfileTrigger:
			start := time.Now()
			profileStateMachine(getconfigCtx, false)
			ctx.ps.CheckMaxTimeTopic(wdName, "getLocalProfileConfigTrigger", start,
				warningTime, errorTime)
		case <-ticker.C:
			start := time.Now()
			profileStateMachine(getconfigCtx, false)
			ctx.ps.CheckMaxTimeTopic(wdName, "getLocalProfileConfigTimer", start,
				warningTime, errorTime)
		case <-stillRunning.C:
		}
		ctx.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

func parseLocalProfile(localProfileBytes []byte) (*profile.LocalProfile, error) {
	var localProfile = &profile.LocalProfile{}
	err := proto.Unmarshal(localProfileBytes, localProfile)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling failed: %v", err)
	}
	return localProfile, nil
}

func parseAndValidateLocalProfile(localProfileBytes []byte, getconfigCtx *getconfigContext) (*profile.LocalProfile, error) {
	localProfile, err := parseLocalProfile(localProfileBytes)
	if err != nil {
		return nil, fmt.Errorf("parseAndValidateLocalProfile: parseLocalProfile: %v", err)
	}
	if localProfile.GetServerToken() != getconfigCtx.profileServerToken {
		// send something to ledmanager ??
		return nil, fmt.Errorf("parseAndValidateLocalProfile: missamtch ServerToken for local profile server")
	}
	return localProfile, nil
}

// read saved local profile in case of particular reboot reason
func readSavedLocalProfile(getconfigCtx *getconfigContext, validate bool) (*profile.LocalProfile, error) {
	localProfileMessage, err := readSavedProtoMessage(
		getconfigCtx.zedagentCtx.globalConfig.GlobalValueInt(types.StaleConfigTime),
		filepath.Join(checkpointDirname, savedLocalProfileFile), false)
	if err != nil {
		return nil, fmt.Errorf("readSavedLocalProfile: %v", err)
	}
	if localProfileMessage != nil {
		log.Function("Using saved local profile")
		if validate {
			return parseAndValidateLocalProfile(localProfileMessage, getconfigCtx)
		}
		return parseLocalProfile(localProfileMessage)
	}
	return nil, nil
}

//prepareLocalProfileServerMap process configuration of network instances to find match with defined localServerURL
//returns the srcIP and processed url for the zero or more network instances on which the localProfileServer might be hosted
//based on a IP or hostname in dns records match apps
//in form bridge name -> slice of urlAndSrcIP
func prepareLocalProfileServerMap(localServerURL string, getconfigCtx *getconfigContext) (map[string][]*urlAndSrcIP, error) {
	u, err := url.Parse(localServerURL)
	if err != nil {
		return nil, fmt.Errorf("checkAndPrepareLocalIP: url.Parse: %s", err)
	}
	res := make(map[string][]*urlAndSrcIP)
	appendURLAndSrcIPMap := func(resMap map[string][]*urlAndSrcIP, intf string, obj *urlAndSrcIP) {
		if _, ok := resMap[intf]; !ok {
			resMap[intf] = []*urlAndSrcIP{}
		}
		resMap[intf] = append(resMap[intf], obj)
	}
	appNetworkStatuses := getconfigCtx.subAppNetworkStatus.GetAll()
	networkInstanceConfigs := getconfigCtx.pubNetworkInstanceConfig.GetAll()
	localProfileServerHostname := u.Hostname()
	localProfileServerIP := net.ParseIP(localProfileServerHostname)
	for _, entry := range appNetworkStatuses {
		appNetworkStatus := entry.(types.AppNetworkStatus)
		for _, ulStatus := range appNetworkStatus.UnderlayNetworkList {
			bridgeIP := net.ParseIP(ulStatus.BridgeIPAddr)
			if bridgeIP == nil {
				continue
			}
			if localProfileServerIP != nil {
				//check if defined IP of localServer is equals with allocated IP of app
				if ulStatus.AllocatedIPv4Addr == localProfileServerIP.String() {
					appendURLAndSrcIPMap(res, ulStatus.Bridge,
						&urlAndSrcIP{actualURL: localServerURL, srcIP: bridgeIP})
				}
				continue
			}
			//check if defined hostname of localServer is in DNS records
			for _, ni := range networkInstanceConfigs {
				networkInstanceConfig := ni.(types.NetworkInstanceConfig)
				for _, dnsNameToIPList := range networkInstanceConfig.DnsNameToIPList {
					if dnsNameToIPList.HostName != localProfileServerHostname {
						continue
					}
					for _, ip := range dnsNameToIPList.IPs {
						localServerURLReplaced := strings.Replace(localServerURL, localProfileServerHostname,
							ip.String(), 1)
						log.Functionf(
							"prepareLocalProfileServerMap: will use %s for bridge %s",
							localServerURLReplaced, ulStatus.Bridge)
						appendURLAndSrcIPMap(res, ulStatus.Bridge,
							&urlAndSrcIP{actualURL: localServerURLReplaced, srcIP: bridgeIP})
					}
				}
			}
		}
	}
	return res, nil
}

// getLocalProfileConfig connects to local profile server to fetch current profile
func getLocalProfileConfig(localServerURL string, getconfigCtx *getconfigContext) (*profile.LocalProfile, error) {

	log.Functionf("getLocalProfileConfig(%s)", localServerURL)

	localServerMap, err := prepareLocalProfileServerMap(localServerURL, getconfigCtx)
	if err != nil {
		return nil, fmt.Errorf("getLocalProfileConfig: prepareLocalProfileServerMap: %s", err)
	}

	if len(localServerMap) == 0 {
		return nil, fmt.Errorf(
			"getLocalProfileConfig: cannot find any configured apps for localServerURL: %s",
			localServerURL)
	}

	var errList []string
	for bridgeName, urlAndSrcIPs := range localServerMap {
		for _, el := range urlAndSrcIPs {
			resp, contents, err := zedcloud.SendLocal(zedcloudCtx, el.actualURL, bridgeName, el.srcIP, 0, nil)
			if err != nil {
				errList = append(errList, fmt.Sprintf("SendLocal: %s", err))
				continue
			}
			if resp.StatusCode != http.StatusOK {
				errList = append(errList, fmt.Sprintf("SendLocal: wrong response status code: %d",
					resp.StatusCode))
				continue
			}
			if err := validateProtoMessage(el.actualURL, resp); err != nil {
				// send something to ledmanager ???
				errList = append(errList, fmt.Sprintf("validateProtoMessage: resp header error: %s", err))
				continue
			}
			localProfile, err := parseAndValidateLocalProfile(contents, getconfigCtx)
			if err != nil {
				errList = append(errList, fmt.Sprintf("parseAndValidateLocalProfile: %s", err))
				continue
			}
			return localProfile, nil
		}
	}
	return nil, fmt.Errorf("getLocalProfileConfig: all attempts failed: %s", strings.Join(errList, ";"))
}

//writeOrTouchReceivedLocalProfile updates modification time of received LocalProfile in case of no changes
//or updates content of received LocalProfile in case of changes
func writeOrTouchReceivedLocalProfile(getconfigCtx *getconfigContext, localProfile *profile.LocalProfile) {
	if getconfigCtx.localProfile == localProfile.GetLocalProfile() &&
		getconfigCtx.profileServerToken == localProfile.GetServerToken() {
		touchProtoMessage(savedLocalProfileFile)
		return
	}
	contents, err := proto.Marshal(localProfile)
	if err != nil {
		log.Errorf("writeOrTouchReceivedLocalProfile Marshalling failed: %s", err)
		return
	}
	writeProtoMessage(savedLocalProfileFile, contents)
	return
}

//parseProfile process local and global profile configuration
//must be called before processing of app instances from config
func parseProfile(ctx *getconfigContext, config *zconfig.EdgeDevConfig) {
	log.Functionf("parseProfile start: globalProfile: %s localProfile: %s",
		ctx.globalProfile, ctx.localProfile)
	if ctx.globalProfile != config.GlobalProfile {
		log.Noticef("parseProfile: GlobalProfile changed from %s to %s",
			ctx.globalProfile, config.GlobalProfile)
		ctx.globalProfile = config.GlobalProfile
	}
	if ctx.localProfileServer != config.LocalProfileServer {
		log.Noticef("parseProfile: LocalProfileServer changed from %s to %s",
			ctx.localProfileServer, config.LocalProfileServer)
		ctx.localProfileServer = config.LocalProfileServer
		triggerGetLocalProfile(ctx)
	}
	ctx.profileServerToken = config.ProfileServerToken
	profileStateMachine(ctx, true)
	log.Functionf("parseProfile done globalProfile: %s currentProfile: %s",
		ctx.globalProfile, ctx.currentProfile)
}

//determineCurrentProfile return current profile based on localProfile, globalProfile
func determineCurrentProfile(ctx *getconfigContext) string {
	if ctx.localProfile == "" {
		return ctx.globalProfile
	}
	return ctx.localProfile
}

//triggerGetLocalProfile notifies task to reload local profile from profileServer
func triggerGetLocalProfile(ctx *getconfigContext) {
	log.Functionf("triggerGetLocalProfile")
	select {
	case ctx.localProfileTrigger <- Notify{}:
	default:
	}
}

// run state machine to handle changes to globalProfile, localProfileServer,
// or to do periodic fetch of the local profile
// If skipFetch is set we do not look for an update from a localProfileServer
// but keep the current localProfile
func profileStateMachine(ctx *getconfigContext, skipFetch bool) {
	localProfile := getLocalProfile(ctx, skipFetch)
	if ctx.localProfile != localProfile {
		log.Noticef("local profile changed from %s to %s",
			ctx.localProfile, localProfile)
		ctx.localProfile = localProfile
	}
	currentProfile := determineCurrentProfile(ctx)
	if ctx.currentProfile != currentProfile {
		log.Noticef("current profile changed from %s to %s",
			ctx.currentProfile, currentProfile)
		ctx.currentProfile = currentProfile
		publishZedAgentStatus(ctx)
	}
}

// getLocalProfile returns the local profile to use, and cleans up ctx and
// checkpoint when the local profile server has been removed. If skipCheck
// is not set it will query the local profile server.
// It returns the last known value until it gets a response from the server
// or localProfileServer is cleared.
func getLocalProfile(ctx *getconfigContext, skipFetch bool) string {
	localProfileServer := ctx.localProfileServer
	if localProfileServer == "" {
		if ctx.localProfile != "" {
			log.Noticef("clearing localProfile checkpoint since no server")
			cleanSavedProtoMessage(savedLocalProfileFile)
		}
		return ""
	}
	if skipFetch {
		return ctx.localProfile
	}
	localProfileURL, err := getLocalProfileURL(localProfileServer)
	if err != nil {
		log.Errorf("getLocalProfile getLocalProfileURL: %s", err)
		return ""
	}
	localProfileConfig, err := getLocalProfileConfig(localProfileURL, ctx)
	if err != nil {
		log.Errorf("getLocalProfile getLocalProfileConfig: %s", err)
		// Return last known value
		return ctx.localProfile
	}
	localProfile := localProfileConfig.GetLocalProfile()
	writeOrTouchReceivedLocalProfile(ctx, localProfileConfig)
	return localProfile
}

//processSavedProfile reads saved local profile and set it
func processSavedProfile(ctx *getconfigContext) {
	localProfile, err := readSavedLocalProfile(ctx, false)
	if err != nil {
		log.Functionf("processSavedProfile: readSavedLocalProfile %s", err)
		return
	}
	if localProfile != nil {
		log.Noticef("starting with localProfile %s", localProfile.LocalProfile)
		ctx.localProfile = localProfile.LocalProfile
	}
}
