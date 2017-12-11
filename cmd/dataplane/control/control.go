package main

import (
	"fmt"
	"github.com/zededa/go-provision/dataplane/fib"
	"github.com/zededa/go-provision/dataplane/etr"
    "encoding/json"
    "net"
    "log"
	"os"
	"time"
	"os/signal"
	"syscall"
)

const lispConfigDir = "/opt/zededa/lisp/"
const configHolePath = lispConfigDir + "lisp-ipc-data-plane"
const lispersDotNetItr = lispConfigDir + "lispers.net-itr"
var   configPipe net.Listener
var   puntChannel chan []byte

const (
    MAPCACHETYPE = "map-cache"
    DATABASEMAPPINGSTYPE = "database-mappings"
    INTERFACESTYPE = "interfaces"
    DECAPKEYSTYPE = "decap-keys"
)

func main() {
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
			log.Fatal("Failed deleting the old lisp-ipc-data-plane socket: %s\n",
						err)
			return
		}
		fmt.Println("Removed old lisp-ipc-data-plane socket")
	}

	configPipe, err := net.ListenUnixgram("unixgram",
								&net.UnixAddr{configHolePath, "unixgram"})
	if err != nil {
		log.Fatal("Opening config hole: %s failed with err: %s\n",
					configHolePath, err)
		fmt.Printf("Opening config hole: %s failed with err: %s\n",
					configHolePath, err)
		return
	}

	registerSignalHandler()
	startPuntProcessor()
	handleConfig(configPipe)
}

func startPuntProcessor() {
	var conn net.Conn
	/**
	 * Start a thread that connects to lispers.net-itr unix
	 * dgram socket.
	 *
	 * This thread should keep re-trying till it can get a clint
	 * connection to lispers.net-itr
	 */
	puntChannel = make(chan []byte, 100)

	for {
	    fmt.Println("Trying for connection to lispers.net-itr")
	    if _, err := os.Stat(lispersDotNetItr); err != nil {
			// lispers.net control plane has not created the server socket yet
			// sleeping for 1 second before re-trying again
			time.Sleep(5000 * time.Millisecond)
			continue
	    }

		lconn, err := net.Dial("unix", lispersDotNetItr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Client connection to %s cannot he opened: %s\n",
						lispersDotNetItr, err)
			return
		}
		fmt.Printf("Connection established to %s\n", lispersDotNetItr)
		conn = lconn
		break
	}

	go func(conn net.Conn, puntChannel chan []byte) {
		defer close(puntChannel)
		// Keep reading from punt channel and write punts to lispers.net-itr
		for {
			puntMsg := <-puntChannel
			_, err := conn.Write(puntMsg)
			if err != nil {
				// something bad happened while writing to lispers.net
				// It could be temporary. We will keep going.
				fmt.Fprintf(os.Stderr, "Error writing to punt channel %s: %s\n",
							lispersDotNetItr, err)
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
			fmt.Println("Received signal:", sig)
			switch sig {
			case syscall.SIGUSR1:
				fib.ShowMapCacheEntries()
				fib.ShowDecapKeys()
				fib.ShowIfaceIIDs()
				fib.ShowIfaceEIDs()
			}
		}
	}()
}

func handleConfig(c *net.UnixConn) {
	defer c.Close()
	buf := make([]byte, 1024)
	for {
		n, err := c.Read(buf[:])
		if err != nil {
			log.Printf("Error reading from client: %s\n", err)
			c.Close()
			return
		} else {
			fmt.Println(string(buf[0:n]))
			handleLispMsg(buf[0:n])
		}
	}
}

func handleLispMsg(msg []byte) {
	// Unmarshal to find type of message
	var msgType Type
	err := json.Unmarshal(msg, &msgType)
	if err != nil {
		fmt.Println("Error processing JSON message")
		fmt.Println("Error:", err)
		return
	}

	switch msgType.Type {
	case MAPCACHETYPE:
		fmt.Println("Got map-cache entry message")
		handleMapCache(msg)
	case DATABASEMAPPINGSTYPE:
		fmt.Println("Got database-mappings entry message")
		handleDatabaseMappings(msg)
	case INTERFACESTYPE:
		fmt.Println("Got interfaces entry message")
		handleInterfaces(msg)
	case DECAPKEYSTYPE:
		handleDecapKeys(msg)
	default:
		log.Println("Unknown message type received")
	}
}
