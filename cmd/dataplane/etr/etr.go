package etr

import (
	"fmt"
	"log"
	"net"
	"syscall"
	"io/ioutil"
	"encoding/json"
	"github.com/zededa/go-provision/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pfring"
	"github.com/zededa/go-provision/dataplane/fib"
)

const uplinkFileName = "/var/tmp/zedrouter/config/global"

func StartETR(ephPort int) (*net.UDPConn, *pfring.Ring, int, int) {
	log.Println("Starting ETR thread on port 4341")
	log.Printf("Starting ETR thread on ephemeral port %d\n", ephPort)

	// create a udp server socket and start listening on port 4341
	// XXX Using ipv4 underlay for now. Will have to figure out v6 underlay case.
	etrServer, err := net.ResolveUDPAddr("udp4", ":4341")
	if err != nil {
		log.Printf("Error resolving ETR socket address: %s\n", err)
		return nil, nil, -1, -1
	}
	serverConn, err := net.ListenUDP("udp4", etrServer)
	if err != nil {
		log.Printf("Unable to start ETR server on :4341: %s\n", err)
		return nil, nil, -1, -1
	}

	// Create a raw socket for injecting decapsulated packets
	fd1, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Printf("Creating ETR raw socket for packet injection failed: %s\n", err)
		serverConn.Close()
		return nil, nil, -1, -1
	}

	// start processing packets. This loop should never end.
	go ProcessETRPkts(fd1, serverConn)

	ring := SetupEtrPktCapture(ephPort)
	if ring == nil {
		log.Printf("Unable to create ETR packet capture.\n")
		return serverConn, nil, fd1, -1
	}

	fd2, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Printf("Creating second ETR raw socket for packet injection failed: %s\n", err)
		ring.Disable()
		ring.Close()
		return serverConn, nil, fd1, -1
	}
	go ProcessCapturedPkts(fd2, ring)

	return serverConn, ring, fd1, fd2
}

func verifyAndInject(fd6 int, buf []byte, n int) bool {
	//var pktEid net.IP
	iid := fib.GetLispIID(buf[0:8])
	if iid == uint32(0xFFFFFF) {
		return true
	}
	log.Println("IID of packet is:", iid)

	var destAddr [16]byte
	for i, _ := range destAddr {
		// offset is lisp hdr size + start offset of ip addresses in v6 hdr
		destAddr[i] = buf[8+24+i]
		//pktEid[i] = destAddr[i]
	}
	/*
		packet := gopacket.NewPacket(buf[8: n],
									layers.LinkTypeIPv6,
									gopacket.Default)
		if packet == nil {
			log.Printf("Packet decode failure\n");
			return
		}

		ip6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ip6Layer == nil {
			log.Printf("Extracting ipv6 header failed\n")
			return
		}

		ipHeader := ip6Layer.(*layers.IPv6)
		dstAddr := ipHeader.DstIP
	*/

	/*
		eids := fib.LookupIfaceEids(iid)
		matchFound := false

		for _, eid := range eids {
			if pktEid.Equal(eid) == true {
				matchFound = true
			}
		}
		if matchFound == false {
			log.Printf(
			"Incoming packet is not destined to any of the EIDs belonging to us.\n")
			log.Printf(
			"Incoming packet is destined to %s.\n", destAddr)
			return
		}
	*/

	/*
		v6Addr := ipHeader.DstIP.To16()
		var destAddr [16]byte
		for i, _ := range destAddr {
			destAddr[i] = v6Addr[i]
		}
	*/

	err := syscall.Sendto(fd6, buf[8:n], 0, &syscall.SockaddrInet6{
		Port:   0,
		ZoneId: 0,
		Addr:   destAddr,
	})
	if err != nil {
		log.Printf("Failed injecting ETR packet: %s.\n", err)
		return false
	}
	return true
}

func SetupEtrPktCapture(ephemeralPort int) *pfring.Ring {
	var globalConfig types.DeviceNetworkConfig

	// Get the interface on which to listen for packets.
	// Current uplink interface information is stored in
	// /var/tmp/zedrouter/config/global
	cb, err := ioutil.ReadFile(uplinkFileName)
	if err != nil {
		log.Printf("%s for %s\n", err, uplinkFileName)
		return nil
	}
	if err := json.Unmarshal(cb, &globalConfig); err != nil {
		log.Printf("%s DeviceNetworkConfig file: %s\n",
			err, uplinkFileName)
		return nil
	}

	// XXX hack hack
	// We open only the first interface in list for packet capture.
	// Later in future all interfaces in the list will have to be opened
	// for packet capture.
	/*
	for _, u := range globalConfig.Uplink {
		// open for packet capture
	}
	*/

	upLink := globalConfig.Uplink[0]

	ring, err := pfring.NewRing(upLink, 65536, pfring.FlagPromisc)
	if err != nil {
		log.Printf("ETR packet capture on interface %s failed: %s\n",
		upLink, err)
		return nil
	}

	// Set filter for UDP, source port = 4341, destination port = given ephemeral
	ring.SetDirection(pfring.ReceiveOnly)
	ring.SetSocketMode(pfring.ReadOnly)

	filter := fmt.Sprintf("udp dst port %d and udp src port 4341", ephemeralPort)
	ring.SetBPFFilter(filter)

	ring.SetPollWatermark(5)
	ring.SetPollDuration(5)

	err = ring.Enable()
	if err != nil {
		log.Printf("Enabling pfring on interface %s failed: %s\n", upLink, err)
		return nil
	}
	return ring
}

func ProcessETRPkts(fd6 int, serverConn *net.UDPConn) bool {
	// start processing packets. This loop should never end.
	buf := make([]byte, 65536)
	log.Printf("Started processing captured packets in ETR\n")

	for {
		n, _, err := serverConn.ReadFromUDP(buf)
		log.Println("XXXXX Received", n, "bytes in ETR")
		if err != nil {
			log.Printf("Fatal error during ETR processing\n")
			return false
		}
		ok := verifyAndInject(fd6, buf, n)
		if ok == false {
			log.Printf("Failed injecting ETR packet from port 4341\n")
		}
	}
}

func ProcessCapturedPkts(fd6 int, ring *pfring.Ring) {
	var pktBuf [65536]byte
	log.Printf("Started processing captured packets in ETR\n")

	for {
		ci, err := ring.ReadPacketDataTo(pktBuf[:])
		if err != nil {
			log.Printf("Error capturing packets: %s\n", err)
			log.Printf("It could be the ring closure leading to this.\n")
			return
		}
		log.Printf("XXXXX Captured ETR packet\n")
		capLen := ci.CaptureLength
		packet := gopacket.NewPacket(
			pktBuf[:capLen],
			layers.LinkTypeEthernet,
			gopacket.DecodeOptions{Lazy: true, NoCopy: true})

		appLayer := packet.ApplicationLayer()
		payload := appLayer.Payload()
		//log.Println(payload)
		ok := verifyAndInject(fd6, payload, len(payload))
		if ok == false {
			log.Printf("Failed injecting ETR packet from ephemeral port\n")
		}
	}
}
