// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Implements ITR functionality. StartItrThread should be started as a go routine.
// Each ITR threads listens on one of the overlay interfaces for packets. Captured
// packets are encapsulated and sent to the destination RLOC.

package itr

import (
	"encoding/json"
	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
	//"github.com/google/gopacket/pfring"
	"github.com/lf-edge/eve/pkg/pillar/dataplane/dptypes"
	"github.com/lf-edge/eve/pkg/pillar/dataplane/fib"
	log "github.com/sirupsen/logrus"
	"net"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const SNAPLENGTH = 65536

var debug bool = false

func InitITR(debugFlag bool) {
	debug = debugFlag
	fib.InitItrCryptoPort()
}

func disableIntfHardwareFeatures(ifname string) {
	cmd := "ethtool"
	args := []string{"-K", ifname, "tx", "off", "sg", "off",
		"tso", "off", "ufo", "off", "gso", "off"}

	_, err := exec.Command(cmd, args...).Output()
	if err != nil {
		log.Errorf("disableIntfHardwareFeatures: Failed disabling hardware features on %s", ifname)
	} else {
		log.Infof("disableIntfHardwareFeatures: Disabled hardware features on %s", ifname)
	}
}

func StartItrThread(threadName string,
	//ring *pfring.Ring,
	handle *afpacket.TPacket,
	//killChannel chan bool,
	umblical chan dptypes.ITRConfiguration,
	puntChannel chan []byte) {

	log.Infof("StartItrThread: Starting ITR thread: %s", threadName)
	// Kill channel will no longer be needed
	// if we return from this function

	//if ring == nil {
	if handle == nil {
		log.Errorf("StartItrThread: Packet capture setup for interface %s failed",
			threadName)
		return
	}
	defer handle.Close()

	// Disable hardware features on interface
	disableIntfHardwareFeatures(threadName)

	// create raw socket pair for sending LISP packets out
	fd4, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Errorf("StartItrThread: "+
			"Failed creating IPv4 raw socket for %s: %s",
			threadName, err)
		return
	}
	err = syscall.SetsockoptInt(
		fd4, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 65536)
	if err != nil {
		log.Errorf("StartItrThread: Thread %s: "+
			"Setting socket buffer size failed: %s",
			threadName, err)
	}
	defer syscall.Close(fd4)

	err = syscall.SetsockoptInt(fd4, syscall.SOL_SOCKET,
		syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DONT)
	if err != nil {
		log.Errorf(
			"StartItrThread: "+
				"Disabling path MTU discovery for ipv4 socket failed: %s",
			err)
	}
	/*
		err = syscall.SetsockoptInt(fd4, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 0)
		if err != nil {
			log.Errorf("Disabling IP_HDRINCL failed: %s.", err)
		}
	*/

	fd6, err := syscall.Socket(
		syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Errorf("StartItrThread: "+
			"Failed creating IPv6 raw socket for %s: %s",
			threadName, err)
		return
	}
	err = syscall.SetsockoptInt(
		fd6, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 65536)
	if err != nil {
		log.Errorf("StartItrThread: "+
			"Thread %s: Setting socket buffer size failed: %s",
			threadName, err)
	}

	err = syscall.SetsockoptInt(fd6, syscall.SOL_SOCKET,
		syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DONT)
	if err != nil {
		log.Errorf(
			"StartItrThread: "+
				"Disabling path MTU discovery for ipv6 socket failed: %s",
			err)
	}
	defer syscall.Close(fd6)

	ivLow := uint64(fib.GenerateRandToken(0x7fffffffffffffff))
	ivHigh := uint32(fib.GenerateRandToken(0x7fffffff))

	itrLocalData := new(dptypes.ITRLocalData)
	itrLocalData.Fd4 = fd4
	itrLocalData.Fd6 = fd6
	itrLocalData.IvHigh = ivHigh
	itrLocalData.IvLow = ivLow

	itrLocalData.LayerParser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet, &itrLocalData.Eth, &itrLocalData.Ip4,
		&itrLocalData.Ip6, &itrLocalData.Udp, &itrLocalData.Tcp)

	if itrLocalData.LayerParser == nil {
		log.Fatal("StartItrThread: ERROR: Packet decode parser creation failed")
	}

	// We do not want the parser exiting with error when it encounters
	// a layer that it does not have parser for.
	// XXX This option is not present in release v1.1.14 of gopacket.
	// We'll have to move to the next release when available.
	//itrLocalData.LayerParser.IgnoreUnsupported = true

	//startWorking(threadName, ring, killChannel, puntChannel,
	//startWorking(threadName, handle, killChannel, puntChannel,
	//	itrLocalData)
	startWorking(threadName, handle, umblical, puntChannel,
		itrLocalData)

	// If startWorking returns, it means the control thread wants
	// this thread to die.
	return
}

/*
// Opens up the pfing on interface and sets up packet capture.
func SetupPacketCapture(ifname string, snapLen uint32) *pfring.Ring {
	// create a new pf_ring to capture packets from our interface
	ring, err := pfring.NewRing(ifname, SNAPLENGTH, pfring.FlagPromisc)
*/
func SetupPacketCapture(iface string, snapLen int) *afpacket.TPacket {
	log.Debugf("SetupPacketCapture: Start packet capture from interface %s", iface)
	const (
		// Memory map buffer size in mega bytes
		mmapBufSize int = 24

		// set interface in promiscous mode
		promisc bool = true
	)

	frameSize := snapLen
	blockSize := frameSize * 128
	numBlocks := 2

	if !strings.HasPrefix(iface, "dbo1x") {
		// Capture packets from domU network's sister interface.
		// DomUs can some times send big packets. This can break MTU
		// requirement of uplink interfaces. go-provision would create
		// a sister interface to network bridge with a smaller MTU like 1280.
		// Data plane should capture packets from the sister interface instead
		// of the lisp network bridge directly.
		iface = "s" + iface
	}
	tPacket, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptFrameSize(frameSize),
		afpacket.OptBlockSize(blockSize),
		afpacket.OptNumBlocks(numBlocks),
		afpacket.OptPollTimeout(5*time.Second),
		afpacket.OptBlockTimeout(1*time.Millisecond),
		afpacket.OptTPacketVersion(afpacket.TPacketVersion3))
	if err != nil {
		//log.Errorf("SetupPacketCapture: PF_RING creation for interface %s failed: %s",
		//	ifname, err)
		log.Errorf("SetupPacketCapture: Error: "+
			"Opening afpacket interface %s: %s", iface, err)
		return nil
	}

	// Capture ipv6 packets only
	/*
		err = ring.SetBPFFilter("ip6")
		if err != nil {
			log.Errorf(
				"SetupPacketCapture: Setting ipv6 BPF filter on interface %s failed: %s",
				ifname, err)
			ring.Close()
			return nil
		}

		// Make PF_RING capture only transmitted packet
		ring.SetDirection(pfring.TransmitOnly)
	*/

	filter := "ip or ip6"
	log.Debugf("SetupPacketCapture: Compiling BPF filter (%s) for interface %s",
		filter, iface)
	ins, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet,
		1600, filter)
	if err != nil {
		log.Errorf("SetupPacketCapture: Compiling BPF filter %s failed: %s", filter, err)
	} else {
		raw_ins := *(*[]bpf.RawInstruction)(unsafe.Pointer(&ins))
		err = tPacket.SetBPF(raw_ins)
		if err != nil {
			log.Errorf("SetupPacketCapture: Setting BPF filter %s failed: %s", filter, err)
		}
	}
	//err = tPacket.SetBPFFilter("ip6")

	/*
		// set the ring in readonly mode
		ring.SetSocketMode(pfring.ReadOnly)

		ring.SetPollWatermark(1)
		// set a poll duration of 1 hour
		ring.SetPollDuration(60 * 60 * 1000)

		// Enable ring. Packet inflow starts after this.
		err = ring.Enable()
		if err != nil {
			log.Errorf("SetupPacketCapture: Failed enabling PF_RING for interface %s: %s",
				ifname, err)
			ring.Close()
			return nil
		}
		return ring
	*/
	return tPacket
}

// Start capturing and processing packets.
//func startWorking(ifname string, ring *pfring.Ring,
func startWorking(ifname string, handle *afpacket.TPacket,
	//killChannel chan bool, puntChannel chan []byte,
	umblical chan dptypes.ITRConfiguration, puntChannel chan []byte,
	itrLocalData *dptypes.ITRLocalData) {
	var pktBuf [SNAPLENGTH]byte

	iid := fib.LookupIfaceIID(ifname)
	if iid == 0 {
		log.Errorf("startWorking: "+
			"Interface %s's IID cannot be found", ifname)
		return
	}

	log.Debugf("startWorking: Capturing packets from interface %s", ifname)

	// We need the EIDs attached to this interfaces for further processing
	// Keep looking for them every 100ms
	var eids []net.IP
eidLoop:
	for {
		time.Sleep(2 * time.Second)
		select {
		//case <-killChannel:
		case itrConfig := <-umblical:
			if itrConfig.Quit == true {
				log.Infof(
					"startWorking: "+
						"ITR thread %s received terminate from control module.",
					ifname)
				return
			}

			if itrConfig.ItrCryptoPortValid == true {
				log.Infof("startWorking: (%s) Changing ITR crpto port from %d to %d",
					ifname, itrLocalData.ItrCryptoPort, itrConfig.ItrCryptoPort)
				itrLocalData.ItrCryptoPort = itrConfig.ItrCryptoPort
			}
		default:
			// EID map database might not have come yet. Wait for before we start
			// processing packets.
			eids = fib.LookupIfaceEids(iid)
			if eids != nil {
				break eidLoop
			}
			log.Infof("startWorking: "+
				"Re-trying EID lookup for interface %s", ifname)
			continue
		}
	}

	/*
	 * While waiting for packets we should also look for the terminate
	 * message from control module. If control module sends a terminate,
	 * ITR thread should free all its allocated resources, stop processing
	 * packets and exit.
	 */
	for {
		select {
		//case <-killChannel:
		case itrConfig := <-umblical:
			if itrConfig.Quit == true {
				// Channel becomes readable when it's closed.
				// So we terminate the thread either when we see "true" coming in it or
				// when the control thread closes our communication channel.
				log.Infof(
					"startWorking: "+
						"ITR thread %s received terminate from control module.",
					ifname)
				return
			}
			if itrConfig.ItrCryptoPortValid == true {
				log.Infof("startWorking: (%s) Changing ITR crpto port from %d to %d",
					ifname, itrLocalData.ItrCryptoPort, itrConfig.ItrCryptoPort)
				itrLocalData.ItrCryptoPort = itrConfig.ItrCryptoPort
			}
		default:
			//ci, err := ring.ReadPacketDataTo(pktBuf[dptypes.MAXHEADERLEN:])
			ci, err := handle.ReadPacketDataTo(pktBuf[dptypes.MAXHEADERLEN:])
			if err != nil {
				if err == afpacket.ErrTimeout {
					continue
				}
				log.Errorf(
					"startWorking: "+
						"Something wrong with "+
						"packet capture from interface %s: %s",
					ifname, err)
				log.Errorf(
					"startWorking: " +
						"May be we are asked to " +
						"terminate after the hosting domU died.")
				return
			}

			pktLen := ci.CaptureLength
			if pktLen <= 0 {
				// XXX May be add a per thread stat here
				continue
			}
			/*
				packet := gopacket.NewPacket(
					pktBuf[dptypes.MAXHEADERLEN:ci.CaptureLength+dptypes.MAXHEADERLEN],
					layers.LinkTypeEthernet,
					gopacket.DecodeOptions{Lazy: false, NoCopy: true})
			*/

			err = itrLocalData.LayerParser.DecodeLayers(
				pktBuf[dptypes.MAXHEADERLEN:ci.CaptureLength+dptypes.MAXHEADERLEN],
				&itrLocalData.DecodedLayers)

			var srcAddr, dstAddr net.IP
			var protocol layers.IPProtocol
			var ipVersion byte

			/*
				if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil{
					ipVersion = dptypes.IPVERSION4
					ipHeader := ip4Layer.(*layers.IPv4)

					srcAddr  = ipHeader.SrcIP
					dstAddr  = ipHeader.DstIP
					protocol = ipHeader.Protocol
				} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
					ipVersion = dptypes.IPVERSION6
					ipHeader := ip6Layer.(*layers.IPv6)

					srcAddr  = ipHeader.SrcIP
					dstAddr  = ipHeader.DstIP
					protocol = ipHeader.NextHeader
				} else {
					// XXX May be have a global error stat here
					continue
				}
			*/
			for _, layerType := range itrLocalData.DecodedLayers {
				switch layerType {
				case layers.LayerTypeIPv4:
					ipVersion = dptypes.IPVERSION4
					ipHeader := &itrLocalData.Ip4

					srcAddr = ipHeader.SrcIP
					dstAddr = ipHeader.DstIP
					protocol = ipHeader.Protocol
					break
				case layers.LayerTypeIPv6:
					ipVersion = dptypes.IPVERSION6
					ipHeader := &itrLocalData.Ip6

					srcAddr = ipHeader.SrcIP
					dstAddr = ipHeader.DstIP
					protocol = ipHeader.NextHeader
					break
				default:
				}
			}

			// Check if the source address of packet matches with any of the eids
			// assigned to input interface.
			matchFound := false
			for _, eid := range eids {
				if srcAddr.Equal(eid) == true {
					matchFound = true
					break
				}
			}

			if !matchFound {
				// XXX May be add a per thread stat here
				log.Debugf(
					"startWorking: Thread: %s: Input packet with source address %s "+
						"does not have matching EID of interface",
					ifname, srcAddr)
				continue
			}

			/**
			 * Compute hash of packet.
			 */
			var srcAddrBytes, dstAddrBytes uint32
			if ipVersion == dptypes.IPVERSION4 {
				/*
				 * 4 bytes of src addr (xor) 4 bytes of dst addr (xor)
				 * (src port << 16 | dst port)
				 */
				srcAddrBytes = (uint32(srcAddr[0])<<24 |
					uint32(srcAddr[1])<<16 |
					uint32(srcAddr[2])<<8 | uint32(srcAddr[3]))
				dstAddrBytes = (uint32(dstAddr[0])<<24 |
					uint32(dstAddr[1])<<16 |
					uint32(dstAddr[2])<<8 | uint32(dstAddr[3]))
			} else {
				/*
				 * LSB 4 bytes of src addr (xor) LSB 4 bytes of dst addr (xor)
				 * (src port << 16 | dst port)
				 */
				srcAddrBytes = (uint32(srcAddr[12])<<24 |
					uint32(srcAddr[13])<<16 |
					uint32(srcAddr[14])<<8 | uint32(srcAddr[15]))
				dstAddrBytes = (uint32(dstAddr[12])<<24 |
					uint32(dstAddr[13])<<16 |
					uint32(dstAddr[14])<<8 | uint32(dstAddr[15]))
			}

			var ports uint32 = 0
			/*
				transportLayer := packet.TransportLayer()
				if (protocol == layers.IPProtocolUDP) ||
					(protocol == layers.IPProtocolTCP) {
					// This is a byte array of the header
					transportContents := transportLayer.LayerContents()

					// XXX What do we do when there is no transport header? like PING
					if transportContents != nil {
						ports = (uint32(transportContents[0])<<24 |
							uint32(transportContents[1])<<16 |
							uint32(transportContents[2])<<8 |
							uint32(transportContents[3]))
					}
				}
			*/
			switch protocol {
			case layers.IPProtocolTCP:
				srcPort := itrLocalData.Tcp.SrcPort
				dstPort := itrLocalData.Tcp.DstPort
				var dwordSrcPort uint32 = uint32(srcPort) << 16
				ports = uint32(dwordSrcPort | uint32(dstPort))
			case layers.IPProtocolUDP:
				srcPort := itrLocalData.Udp.SrcPort
				dstPort := itrLocalData.Udp.DstPort
				var dwordSrcPort uint32 = uint32(srcPort) << 16
				ports = uint32(dwordSrcPort | uint32(dstPort))
			}

			var hash32 uint32 = srcAddrBytes ^ dstAddrBytes ^ ports

			if debug {
				log.Debugf("startWorking: Packet of length %d captured on interface %s",
					pktLen, ifname)
			}
			LookupAndSend(pktBuf[:],
				uint32(pktLen), ci.Timestamp, iid, hash32,
				ifname, srcAddr, dstAddr,
				puntChannel, itrLocalData)
		}
	}
}

// This function expects the parameter pktBuf to be a statically
// allocated buffer longer than the original packet length.
// We currently use a buffer of length 64K bytes.
//
// Perform lookup into mapcache database and forward if the lookup succeeds.
// If not, buffer the packet and send a punt request to lispers.net for resolution.
// Look for comments inside the function to understand more about what it does.
func LookupAndSend(
	pktBuf []byte,
	capLen uint32,
	timeStamp time.Time,
	iid uint32,
	hash32 uint32,
	ifname string,
	srcAddr net.IP,
	dstAddr net.IP,
	puntChannel chan []byte,
	itrLocalData *dptypes.ITRLocalData) {

	// Look for the map-cache entry required
	mapEntry, punt := fib.LookupAndAdd(iid, dstAddr, timeStamp)

	if mapEntry.Resolved != true {
		// Buffer the packet for processing later

		// Add packet to channel in a non blocking fashion.
		// Buffered packet channel is only 10 entries long.
		pktCopy := make([]byte, capLen)
		copy(pktCopy, pktBuf[dptypes.MAXHEADERLEN:capLen+dptypes.MAXHEADERLEN])
		select {
		case mapEntry.PktBuffer <- &dptypes.BufferedPacket{
			//Packet: packet,
			Packet: pktCopy,
			Hash32: hash32,
		}:
			atomic.AddUint64(&mapEntry.BuffdPkts, 1)
		default:
			log.Debugf("LookupAndSend: "+
				"Packet buffer channel full for EID %s", dstAddr)
			atomic.AddUint64(&mapEntry.TailDrops, 1)
		}

		/**
		 * There is no guarantee that the control thread has not
		 * resolved our unresolved map entry by the time we add packet
		 * to buffered packet channel. We perform the lookup for our
		 * iid, eid once again with read lock and check the resolution
		 * status.
		 *
		 * If the map cache entry is resolved by now, we dequeue one
		 * packet from the buffered packet channel and send it out.
		 * This avoids the case where control thread has already sent
		 * out all buffered packets and our packet sits in the buffered
		 * channel without being noticed.
		 */
		mapEntry, punt1 := fib.LookupAndAdd(iid, dstAddr, timeStamp)
		if mapEntry.Resolved {
			punt = punt1
			select {
			case pkt := <-mapEntry.PktBuffer:
				// Packet read into pktBuf buffer might have changed.
				// It is not safe to pass it's pointer.
				// Extract the packet data from buffered packet
				/*
					pktBytes := pkt.Packet.Data()
					capLen = uint32(len(pktBytes))
				*/
				capLen = uint32(len(pkt.Packet))

				// copy packet bytes into pktBuf at an offset of MAXHEADERLEN bytes
				// ipv6 (40) + UDP (8) + LISP (8) - ETHERNET (14) + LISP IV (16) = 58
				//copy(pktBuf[dptypes.MAXHEADERLEN:], pktBytes)
				copy(pktBuf[dptypes.MAXHEADERLEN:], pkt.Packet)

				// Encapsulate and send packet out
				fib.CraftAndSendLispPacket(pktBuf, capLen, timeStamp,
					pkt.Hash32, mapEntry, iid, itrLocalData)

				// look golang atomic increment documentation to understand ^uint64(0)
				// We are trying to decrement the counter here by 1
				atomic.AddUint64(&mapEntry.BuffdPkts, ^uint64(0))

				// XXX We do not use these counters now. Might need in future.
				// Increment packet, byte counts
				//atomic.AddUint64(&mapEntry.Packets, 1)
				//atomic.AddUint64(&mapEntry.Bytes, uint64(capLen))
			default:
				// We do not want to get blocked and keep waiting
				// when there are no packets in the buffer channel.
			}
		} else {
			// Look for the default route
			// Prepare lookup key based on the packet family (IPv4 or IPv6)
			isIPv6 := (dstAddr.To4() == nil)
			var defaultPrefix net.IP
			if isIPv6 {
				defaultPrefix = net.ParseIP("::")
			} else {
				defaultPrefix = net.ParseIP("0.0.0.0")
			}
			defaultMap, _ := fib.LookupAndAdd(iid, defaultPrefix, timeStamp)
			if defaultMap.Resolved {
				fib.CraftAndSendLispPacket(pktBuf, capLen, timeStamp,
					hash32, defaultMap, iid, itrLocalData)
			}
		}
	} else {
		// Craft the LISP header, outer layers here and send packet out
		fib.CraftAndSendLispPacket(pktBuf, capLen, timeStamp,
			hash32, mapEntry, iid, itrLocalData)
		//atomic.AddUint64(&mapEntry.Packets, 1)
		//atomic.AddUint64(&mapEntry.Bytes, uint64(capLen))
	}
	if punt == true {
		// We will have to put a punt request on the control
		// module's channel
		puntEntry := dptypes.PuntEntry{
			Type:  "discovery",
			Deid:  dstAddr,
			Seid:  srcAddr,
			Iface: ifname,
		}
		puntMsg, err := json.Marshal(puntEntry)
		if err != nil {
			log.Errorf("LookupAndSend: "+
				"Marshaling punt entry failed %s: %s",
				puntEntry, err)
		} else {
			puntChannel <- puntMsg
			log.Infof("LookupAndSend:Sending punt entry at %s: %s",
				time.Now(), string(puntMsg))
		}
	}
	return
}
