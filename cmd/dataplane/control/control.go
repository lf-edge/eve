package main

import (
	"encoding/json"
	"github.com/zededa/go-provision/dataplane/etr"
	"github.com/zededa/go-provision/dataplane/fib"
	"log"
	"flag"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const lispConfigDir = "/opt/zededa/lisp/"
const configHolePath = lispConfigDir + "lisp-ipc-data-plane"
const lispersDotNetItr = lispConfigDir + "lispers.net-itr"

var configPipe net.Listener
var puntChannel chan []byte

var Version = "No version specified"

const (
	MAPCACHETYPE         = "map-cache"
	DATABASEMAPPINGSTYPE = "database-mappings"
	INTERFACESTYPE       = "interfaces"
	DECAPKEYSTYPE        = "decap-keys"
)

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	versionPtr := flag.Bool("v", false, "Version")
	flag.Parse()
	if *versionPtr {
		log.Printf("%s: %s\n", os.Args[0], Version)
		return
	}

	// Initialize databases
	fib.InitIfaceMaps()
	fib.InitMapCache()
	fib.InitDecapTable()
	go etr.StartETR()

	// Initialize ITR thread management
	InitThreadTable()

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

	conn = connectToLispersDotNet()
	if conn == nil {
		log.Printf("Connection to %s not possible.\n", lispersDotNetItr)
		return
	}

	// Spawn a thread that reads the punt messages from other threads and then
	// writes them to lispers.net-itr socket.
	// Punt messages are expected to be in fully formatted json format. This avoids
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
				// Try and write the punt request again
				_, _ = conn.Write(puntMsg)
			}
		}
	}(conn, puntChannel)
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

func handleConfig(c *net.UnixConn) {
	defer c.Close()

	// Create 8k bytes buffer for reading configuration messages.
	buf := make([]byte, 8192)
	for {
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
		log.Println("Processing map-cache entry message")
		handleMapCache(msg)
	case DATABASEMAPPINGSTYPE:
		log.Println("Processing database-mappings entry message")
		handleDatabaseMappings(msg)
	case INTERFACESTYPE:
		log.Println("Processing interfaces entry message")
		handleInterfaces(msg)
	case DECAPKEYSTYPE:
		handleDecapKeys(msg)
	default:
		log.Println("Unknown message type received")
	}
}
