// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Maintains maps for storing ITR/ETR thread information. Also takes care of
// creating new threads and destroying stale ITR/ETR threads.

package main

import (
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/pfring"
	"github.com/zededa/go-provision/dataplane/etr"
	"github.com/zededa/go-provision/dataplane/itr"
	"github.com/zededa/go-provision/types"
	"log"
)

type ThreadEntry struct {
	killChannel chan bool
	ring        *pfring.Ring
	handle      *afpacket.TPacket
}

var threadTable map[string]ThreadEntry

func InitThreadTable() {
	threadTable = make(map[string]ThreadEntry)
}

func DumpThreadTable() {
	for name, _ := range threadTable {
		log.Println(name)
	}
}

// Find the difference between running ITR threads and the threads
// that need to be running according to new configuration.
//
// Kill the ITR threads that are no longer needed and create
// newly required threads.
func ManageItrThreads(interfaces Interfaces) {
	tmpMap := make(map[string]bool)

	// Build a map of threads needed according to new configuration
	for _, iface := range interfaces.Interfaces {
		tmpMap[iface.Interface] = true
	}

	// Kill ITR threads that are not needed with new configuration
	for name, entry := range threadTable {
		// Check if this thread is needed with new configuration and send
		// a kill signal if not.
		if _, ok := tmpMap[name]; !ok {
			// This thread has to die, break the bad news to it
			log.Println("ManageItrThreads: Sending kill signal to", name)
			entry.killChannel <- true

			/*
			// XXX
			// ITR threads use pf_ring for packet capture.
			// pf_ring packet read calls are blocking. If a thread is blocked
			// and there are no packets coming in from the corresponding interface,
			// it can never get unblocked and process messages from kill channel.
			//
			// We delete the pf_ring socket for now, so that the ITR thread blocking
			// calls returns with error.
			//
			// We'll retain the kill channel mechanism for future optimizations.
			close(entry.killChannel)
			entry.ring.Disable()
			entry.ring.Close()
			//close(entry.killChannel)
			*/

			delete(threadTable, name)
		}
	}

	// Create new threads that do not already exist
	for name, _ := range tmpMap {
		if _, ok := threadTable[name]; !ok {
			// This ITR thread has to be given birth to. Find a mom!!
			killChannel := make(chan bool, 1)

			// Start the go thread here
			//ring := itr.SetupPacketCapture(name, 65536)
			handle := itr.SetupPacketCapture(name, 65536)
			log.Println("ManageItrThreads: Creating new ITR thread for", name)
			threadTable[name] = ThreadEntry{
				killChannel: killChannel,
				handle:      handle,
			}
			//go itr.StartItrThread(name, ring, killChannel, puntChannel)
			go itr.StartItrThread(name, handle, killChannel, puntChannel)
		}
	}
}

func ManageETRThread(port int) {
	etr.HandleEtrEphPort(port)
}

func ManageEtrDNS(deviceNetworkStatus types.DeviceNetworkStatus) {
	etr.HandleDeviceNetworkChange(deviceNetworkStatus)
}
