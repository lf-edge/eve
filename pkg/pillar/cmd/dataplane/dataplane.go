// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Main code that starts data plane process. All other modules like fib, itr & etr
// are initialized and started by this control thread code.
// Control code also opens/reads unix sockets to get map-cache and interface fib
// data fron lispers.net process.

package dataplane

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/dataplane/dptypes"
	"github.com/lf-edge/eve/pkg/pillar/dataplane/etr"
	"github.com/lf-edge/eve/pkg/pillar/dataplane/fib"
	"github.com/lf-edge/eve/pkg/pillar/dataplane/itr"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	agentName = "lisp-ztr"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
)

var lispConfigDir string
var configHolePath string
var lispersDotNetItr string

// Dummy since we don't have anything to pass
type dummyContext struct {
}

var configPipe net.Listener
var puntChannel chan []byte

var Version = "No version specified"
var debug = false
var debugOverride bool

func Run() {
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	curpartPtr := flag.String("c", "", "Current partition")
	flag.StringVar(&lispConfigDir, "lisp", "/opt/zededa/lisp", "lispers.net path")
	flag.Parse()

	// Open/Create new log file
	curpart := *curpartPtr
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	logf, err := agentlog.Init(agentName, curpart)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	log.Infof("Dataplane: Using %s for LISP directory.\n", lispConfigDir)
	configHolePath = lispConfigDir + "/lisp-ipc-data-plane"
	lispersDotNetItr = lispConfigDir + "/lispers.net-itr"

	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}

	// Initialize pubsub channels
	// We subsribe to Lisp configuration channel from zedrouter
	// and wait for our configuration. Dataplane will only start
	// processing packets when the configuration from zedrouter has
	// Legacy set to false.
	dataplaneContext := initPubsubChannels()

	log.Infof("Waiting for configuration from zedrouter")
	for {
		select {
		case change := <-dataplaneContext.SubLispConfig.C:
			dataplaneContext.SubLispConfig.ProcessChange(change)
		}
		// We keep waiting till we are enabled
		if dataplaneContext.Legacy == false {
			break
		}
	}

	log.Infof("Starting %s service", agentName)

	// Initialize databases
	fib.InitIfaceMaps()
	fib.InitMapCache(debug, lispConfigDir)
	fib.InitDecapTable()

	// Initialize ITR thread management
	InitThreadTable()

	// Init ITR
	itr.InitITR(debug)

	// Start listening on the Unix domain socket "lisp-ipc-data-plane"
	// lispers.net code uses this socket for sending eid to rloc maps
	// and other configuration
	if _, err := os.Stat(configHolePath); err == nil {
		if err = os.Remove(configHolePath); err != nil {
			log.Errorf("main: Failed deleting the old lisp-ipc-data-plane socket: %s", err)
			return
		}
		log.Infof("main: Removed old lisp-ipc-data-plane socket")
	}

	configPipe, err := net.ListenUnixgram("unixgram",
		&net.UnixAddr{Name: configHolePath, Net: "unixgram"})
	if err != nil {
		log.Errorf("main: Opening config hole: %s failed with err: %s",
			configHolePath, err)
		return
	}

	registerSignalHandler()
	startPuntProcessor()

	// Initialize ETR run status
	etr.InitETRStatus(debug)

	// Start ETR thread that listens on port 4341 for Non-NAT packets
	// Thread that handles NAT piercing will be started by handleEtrNatPort
	// function when lispers.net sends us the ephemeral NAT port information.
	etr.StartEtrNonNat()

	// Initialize and start stats thread
	InitAndStartStatsThread(puntChannel, dataplaneContext)

	// start map cache scrub thread
	StartMapcacheScrubThread()

	// This function should not return.
	handleConfig(configPipe, dataplaneContext)
}

// Handles both create and modify events
func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*dptypes.DataplaneContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s", key)
	debug, _ = agentlog.HandleGlobalConfig(ctx.SubGlobalConfig, agentName,
		debugOverride)
	log.Infof("handleGlobalConfigModify done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*dptypes.DataplaneContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s", key)
	debug, _ = agentlog.HandleGlobalConfig(ctx.SubGlobalConfig, agentName,
		debugOverride)
	log.Infof("handleGlobalConfigDelete done for %s", key)
}

// Handles both create and modify events
func handleExpModify(ctxArg interface{}, key string, statusArg interface{}) {
	ctx := ctxArg.(*dptypes.DataplaneContext)

	status := statusArg.(types.LispDataplaneConfig)
	if key != "global" {
		log.Infof("handleExpModify: ignoring %s", key)
		return
	}
	ctx.Legacy = status.Legacy
	log.Infof("handleExpModify: Legacy status %v", ctx.Legacy)
	log.Infof("handleExpModify: done")
}

func handleExpDelete(ctxArg interface{}, key string, statusArg interface{}) {
	// There is no valid reason for deleting configuration
	// XXX For now just mark our local Legacy flag to false and return
	ctx := ctxArg.(*dptypes.DataplaneContext)
	ctx.Legacy = true
}

func initPubsubChannels() *dptypes.DataplaneContext {
	dataplaneContext := &dptypes.DataplaneContext{}

	// Create pubsub publish channels for LispInfo and Metrics
	pubLispInfoStatus, err := pubsub.Publish(agentName,
		types.LispInfoStatus{})
	if err != nil {
		log.Fatal(err)
	}
	dataplaneContext.PubLispInfoStatus = pubLispInfoStatus

	pubLispMetrics, err := pubsub.Publish(agentName,
		types.LispMetrics{})
	if err != nil {
		log.Fatal(err)
	}
	dataplaneContext.PubLispMetrics = pubLispMetrics

	subLispConfig, err := pubsub.Subscribe("zedrouter",
		types.LispDataplaneConfig{}, false, dataplaneContext)
	if err != nil {
		log.Fatal(err)
	}
	subLispConfig.MaxProcessTimeWarn = warningTime
	subLispConfig.MaxProcessTimeError = errorTime
	subLispConfig.ModifyHandler = handleExpModify
	subLispConfig.CreateHandler = handleExpModify
	subLispConfig.DeleteHandler = handleExpDelete
	dataplaneContext.SubLispConfig = subLispConfig
	subLispConfig.Activate()

	// Look for global config like debug
	subGlobalConfig, err := pubsub.Subscribe("",
		types.ConfigItemValueMap{}, false, dataplaneContext)
	if err != nil {
		log.Fatal(err)
	}
	subGlobalConfig.MaxProcessTimeWarn = warningTime
	subGlobalConfig.MaxProcessTimeError = errorTime
	subGlobalConfig.ModifyHandler = handleGlobalConfigModify
	subGlobalConfig.CreateHandler = handleGlobalConfigModify
	subGlobalConfig.DeleteHandler = handleGlobalConfigDelete
	dataplaneContext.SubGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	return dataplaneContext
}

func connectToLispersDotNet() net.Conn {
	for {
		log.Infof("connectToLispersDotNet: Trying for connection to lispers.net-itr")
		if _, err := os.Stat(lispersDotNetItr); err != nil {
			// lispers.net control plane has not created the server socket yet
			// sleeping for 5 second before re-trying again
			time.Sleep(5000 * time.Millisecond)
			continue
		}

		lconn, err := net.DialUnix("unixgram", nil,
			&net.UnixAddr{Name: lispersDotNetItr, Net: "unixgram"})
		if err != nil {
			log.Errorf("connectToLispersDotNet: Client connection to %s cannot be opened: %s",
				lispersDotNetItr, err)
			time.Sleep(5000 * time.Millisecond)
			continue
		}
		log.Infof("connectToLispersDotNet: Connection established to %s",
			lispersDotNetItr)
		return lconn
	}
}

func startPuntProcessor() {
	var conn net.Conn
	/**
	* Start a thread that connects to lispers.net-itr unix
	* dgram socket.
	*
	* This function (XXX may be thread) should keep re-trying till it can get a client
	* connection to lispers.net-itr unix dgram socket.
	*
	* lispers.net-itr socket is created by Dino's lispers.net python control code.
	 */

	// We do not want data processing ITR threads to get blocked.
	// Create a channel of 100 punts to provide sufficient buffering.
	puntChannel = make(chan []byte, 100)
	if puntChannel == nil {
		log.Fatal("startPuntProcessor: Control thread's punt channel could not be allocated")
	}

	conn = connectToLispersDotNet()
	if conn == nil {
		log.Fatal("startPuntProcessor: Connection to " + lispersDotNetItr + " not possible")
	}

	// We could have restarted. We need to ask lispers.net for the databases again.
	restartEntry := dptypes.RestartEntry{
		Type: "restart",
	}
	restartMsg, err := json.Marshal(restartEntry)
	if err == nil {
		puntChannel <- restartMsg
	}

	// Spawn a thread that reads the punt messages from other threads and then
	// writes them to lispers.net-itr socket.
	// Punt messages are expected to be fully formatted json messages. This avoids
	// the need for other threads to send metadata describing the message type (and
	// reduces a bit of complexity).
	go func(conn net.Conn, puntChannel chan []byte) {
		defer close(puntChannel)
		defer conn.Close()
		// Keep reading from punt channel and write punts to lispers.net-itr
		for {
			puntMsg := <-puntChannel
			_, err := conn.Write(puntMsg)
			if err != nil {
				// something bad happened while writing to lispers.net
				// It could be temporary. We will keep going.
				log.Errorf("Error writing to punt channel %s: %s",
					lispersDotNetItr, err)
				log.Errorf("Retrying connection to lispers.net-itr")
				conn = connectToLispersDotNet()
				if conn == nil {
					log.Errorf("Connection to %s not possible", lispersDotNetItr)
					return
				}
				// This could be an indication that lispers.net has restarted.
				// Lets flush all entries in the map-cache database (deleting all
				// all map-cache entries).
				//
				// After re-start lispers.net will not know about the map-cache
				// entries that dataplane has. This can lead to stale entries living
				// in data plane, unless lispers.net sends explicit deletes.
				// It is required to explicitly tell lispers.net about the entries
				// that we have.

				// XXX May be this is not needed. lispers.net already has a
				// check pointing mechanism that stores the state.
				// Check with Dino if this is needed and how this case can be handled
				// gracefully without interrupting the current moving traffic.
				fib.FlushMapCache()

				// Try and write the punt request again
				_, _ = conn.Write(puntMsg)
			}
		}
	}(conn, puntChannel)
}

func StartMapcacheScrubThread() {
	go fib.MapcacheScrubThread()
}

func InitAndStartStatsThread(puntChannel chan []byte,
	ctx *dptypes.DataplaneContext) {
	go fib.StatsThread(puntChannel, ctx)
}

func registerSignalHandler() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGUSR1)

	go func() {
		for {
			sig := <-sigs
			log.Infof("Received signal: %v", sig)
			switch sig {
			case syscall.SIGUSR1:
				fib.ShowMapCacheEntries()
				fib.ShowDecapKeys()
				fib.ShowIfaceIIDs()
				fib.ShowIfaceEIDs()
				DumpThreadTable()
			}
		}
	}()
}

var deviceNetworkStatus types.DeviceNetworkStatus

func handleDNSModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(types.DeviceNetworkStatus)

	if key != "global" {
		log.Infof("ETR: handleDNSModify: ignoring %s", key)
		return
	}
	log.Infof("ETR: handleDNSModify for %s", key)
	deviceNetworkStatus = status
	log.Infof("ETR: handleDNSModify done for %s", key)
}

func handleDNSDelete(ctxArg interface{}, key string, statusArg interface{}) {
	log.Infof("ETR: handleDNSDelete for %s", key)

	if key != "global" {
		log.Infof("ETR: handleDNSDelete: ignoring %s", key)
		return
	}
	deviceNetworkStatus = types.DeviceNetworkStatus{}
	log.Infof("ETR: handleDNSDelete done for %s", key)
}

func handleConfig(c *net.UnixConn, dpContext *dptypes.DataplaneContext) {
	defer c.Close()

	subDeviceNetworkStatus, err := pubsub.Subscribe("nim",
		types.DeviceNetworkStatus{}, false, nil)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkStatus.MaxProcessTimeWarn = warningTime
	subDeviceNetworkStatus.MaxProcessTimeError = errorTime
	subDeviceNetworkStatus.ModifyHandler = handleDNSModify
	subDeviceNetworkStatus.DeleteHandler = handleDNSDelete
	dpContext.SubDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	// Create 8k bytes buffer for reading configuration messages.
	buf := make([]byte, 8192)
	for {
		select {
		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)
			log.Debugf("handleConfig: Detected a change in DeviceNetworkStatus")
			ManageEtrDNS(deviceNetworkStatus)
		case change := <-dpContext.SubGlobalConfig.C:
			dpContext.SubGlobalConfig.ProcessChange(change)
		default:
			n, err := c.Read(buf[:])
			if err != nil {
				log.Errorf("handleConfig: Error reading from client: %s\n", err)
				c.Close()
				return
			} else {
				handleLispMsg(buf[0:n])
				fib.PublishLispInfoStatus(dpContext)
			}
		}
	}
}

func handleLispMsg(msg []byte) {
	// Unmarshal to find type of message
	var msgType Type
	err := json.Unmarshal(msg, &msgType)
	if err != nil {
		log.Errorf("handleLispMsg: Error processing JSON message: %s", err)
		return
	}

	switch msgType.Type {
	case MAPCACHETYPE:
		log.Debugf("handleLispMsg: Processing map-cache entry message")
		handleMapCache(msg)
	case ENTIREMAPCACHE:
		log.Debugf("handleLispMsg: Processing Mapcache dump")
		handleMapCacheTable(msg)
	case DATABASEMAPPINGSTYPE:
		log.Debugf("handleLispMsg: Processing database-mappings entry message")
		handleDatabaseMappings(msg)
	case INTERFACESTYPE:
		log.Debugf("handleLispMsg: Processing interfaces entry message")
		handleInterfaces(msg)
	case DECAPKEYSTYPE:
		log.Debugf("handleLispMsg: Processing Decap Keys message")
		handleDecapKeys(msg)
	case ETRNATPORT:
		log.Debugf("handleLispMsg: Processing ETR nat port message")
		handleEtrNatPort(msg)
	case ITRCRYPTOPORT:
		log.Debugf("handleLispMsg: Processing ITR crypto port message")
		handleItrCryptoPort(msg)
	default:
		log.Debugf("handleLispMsg: Unknown message (%s) type (%v) received",
			string(msg), msgType.Type)
	}
}
