// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Main code that starts data plane process. All other modules like fib, itr & etr
// are initialized and started by this control thread code.
// Control code also opens/reads unix sockets to get map-cache and interface fib
// data fron lispers.net process.

package main

import (
	"encoding/json"
	"flag"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/lisp/dataplane/dptypes"
	"github.com/zededa/lisp/dataplane/etr"
	"github.com/zededa/lisp/dataplane/fib"
	"github.com/zededa/lisp/dataplane/itr"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	agentName  = "dataplane"
	dnsDirname = "/var/run/zedrouter/DeviceNetworkStatus"
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

func main() {
	// Open/Create new log file
	logf, err := agentlog.Init(agentName)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	flag.StringVar(&lispConfigDir, "lisp", "/opt/zededa/lisp", "lispers.net path")
	flag.Parse()

	log.Printf("Dataplane: Using %s for LISP directory.\n", lispConfigDir)
	configHolePath = lispConfigDir + "/lisp-ipc-data-plane"
	lispersDotNetItr = lispConfigDir + "/lispers.net-itr"

	debug = *debugPtr
	if *versionPtr {
		log.Printf("%s: %s\n", os.Args[0], Version)
		return
	}

	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Printf("Starting %s\n", agentName)

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
			log.Printf("Failed deleting the old lisp-ipc-data-plane socket: %s\n",
				err)
			return
		}
		log.Println("Removed old lisp-ipc-data-plane socket")
	}

	configPipe, err := net.ListenUnixgram("unixgram",
		&net.UnixAddr{configHolePath, "unixgram"})
	if err != nil {
		log.Printf("Opening config hole: %s failed with err: %s\n",
			configHolePath, err)
		log.Printf("Opening config hole: %s failed with err: %s\n",
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
	InitAndStartStatsThread(puntChannel)

	// start map cache scrub thread
	StartMapcacheScrubThread()

	// This function should not return.
	handleConfig(configPipe)
}

func connectToLispersDotNet() net.Conn {
	for {
		log.Println("Trying for connection to lispers.net-itr")
		if _, err := os.Stat(lispersDotNetItr); err != nil {
			// lispers.net control plane has not created the server socket yet
			// sleeping for 5 second before re-trying again
			time.Sleep(5000 * time.Millisecond)
			continue
		}

		lconn, err := net.DialUnix("unixgram", nil,
			&net.UnixAddr{lispersDotNetItr, "unixgram"})
		if err != nil {
			log.Printf("Client connection to %s cannot be opened: %s\n",
				lispersDotNetItr, err)
			//return
			time.Sleep(5000 * time.Millisecond)
			continue
		}
		log.Printf("Connection established to %s\n", lispersDotNetItr)
		return lconn
	}
	return nil
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
		log.Fatal("Control thread's punt channel could not be allocated.\n")
		return
	}

	conn = connectToLispersDotNet()
	if conn == nil {
		log.Fatal("Connection to %s not possible.\n", lispersDotNetItr)
		return
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
				log.Printf("Error writing to punt channel %s: %s\n",
					lispersDotNetItr, err)
				log.Printf("Retrying connection to lispers.net-itr\n")
				conn = connectToLispersDotNet()
				if conn == nil {
					log.Printf("Connection to %s not possible.\n", lispersDotNetItr)
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

func InitAndStartStatsThread(puntChannel chan []byte) {
	go fib.StatsThread(puntChannel)
}

func registerSignalHandler() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGUSR1)

	go func() {
		for {
			sig := <-sigs
			log.Println("Received signal:", sig)
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

func handleDNSModify(ctxArg interface{}, statusFilename string,
	statusArg interface{}) {
	status := cast.CastDeviceNetworkStatus(statusArg)

	if statusFilename != "global" {
		log.Printf("ETR: handleDNSModify: ignoring %s\n", statusFilename)
		return
	}
	log.Printf("ETR: handleDNSModify for %s\n", statusFilename)
	deviceNetworkStatus = status
	log.Printf("ETR: handleDNSModify done for %s\n", statusFilename)
}

func handleDNSDelete(ctxArg interface{}, statusFilename string, statusArg interface{}) {
	log.Printf("ETR: handleDNSDelete for %s\n", statusFilename)

	if statusFilename != "global" {
		log.Printf("ETR: handleDNSDelete: ignoring %s\n", statusFilename)
		return
	}
	deviceNetworkStatus = types.DeviceNetworkStatus{}
	log.Printf("ETR: handleDNSDelete done for %s\n", statusFilename)
}

func handleConfig(c *net.UnixConn) {
	defer c.Close()

	ctx := dataplaneContext{}
	subDeviceNetworkStatus, err := pubsub.Subscribe("zedrouter",
	types.DeviceNetworkStatus{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkStatus.ModifyHandler = handleDNSModify
	subDeviceNetworkStatus.DeleteHandler = handleDNSDelete
	ctx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	// Create 8k bytes buffer for reading configuration messages.
	buf := make([]byte, 8192)
	for {
		select {
		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)
			if debug {
				log.Println("Detected a change in DeviceNetworkStatus")
			}
			ManageEtrDNS(deviceNetworkStatus)
		default:
			n, err := c.Read(buf[:])
			if err != nil {
				log.Printf("Error reading from client: %s\n", err)
				c.Close()
				return
			} else {
				handleLispMsg(buf[0:n])
			}
		}
	}
}

func handleLispMsg(msg []byte) {
	// Unmarshal to find type of message
	var msgType Type
	err := json.Unmarshal(msg, &msgType)
	if err != nil {
		log.Println("Error processing JSON message")
		log.Println("Error:", err)
		return
	}

	switch msgType.Type {
	case MAPCACHETYPE:
		if debug {
			log.Println("Processing map-cache entry message")
		}
		handleMapCache(msg)
	case ENTIREMAPCACHE:
		if debug {
			log.Println("Processing Mapcache dump")
		}
		handleMapCacheTable(msg)
	case DATABASEMAPPINGSTYPE:
		if debug {
			log.Println("Processing database-mappings entry message")
		}
		handleDatabaseMappings(msg)
	case INTERFACESTYPE:
		if debug {
			log.Println("Processing interfaces entry message")
		}
		handleInterfaces(msg)
	case DECAPKEYSTYPE:
		if debug {
			log.Println("Processing Decap Keys message")
		}
		handleDecapKeys(msg)
	case ETRNATPORT:
		if debug {
			log.Println("Processing ETR nat port message")
		}
		handleEtrNatPort(msg)
	case ITRCRYPTOPORT:
		if debug {
			log.Println("Processing ITR crypto port message")
		}
		handleItrCryptoPort(msg)
	default:
		if debug {
			log.Println(string(msg))
			log.Println("Unknown message type received")
		}
	}
}
