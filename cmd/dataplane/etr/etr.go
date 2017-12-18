package etr

import (
	"log"
	"net"
	"syscall"
	//"github.com/google/gopacket"
	//"github.com/google/gopacket/layers"
	"github.com/zededa/go-provision/dataplane/fib"
)

func StartETR() bool {
	log.Println("Starting ETR thread on port 4341")
	// create a udp server socket and start listening on port 4341
	// XXX Using ipv4 underlay for now. Will have to figure out v6 underlay case.
	server, err := net.ResolveUDPAddr("udp4", ":4341")
	if err != nil {
		log.Printf("Error resolving ETR socket address\n")
		return false
	}
	serverConn, err := net.ListenUDP("udp4", server)
	if err != nil {
		log.Printf("Unable to start ETR server on :4341: %s\n", err)
		return false
	}
	defer serverConn.Close()

	// Create a raw socket for injecting decapsulated packets
	fd6, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Printf("Creating ETR raw socket for packet injection failed.\n")
		return false
	}
	defer syscall.Close(fd6)

	buf := make([]byte, 65536)

	// start processing packets. This loop should never end.
	for {
		n, _, err := serverConn.ReadFromUDP(buf)
		log.Println("Received", n, "bytes in ETR")
		if err != nil {
			log.Printf("Fatal error during ETR processing\n")
			return false
		}
		verifyAndInject(fd6, buf, n)
	}

	return true
}

func verifyAndInject(fd6 int, buf []byte, n int) {
	//var pktEid net.IP
	iid := fib.GetLispIID(buf[0:8])
	log.Println("IID of packet is:", iid)
	log.Println("Inner packet is:")
	for _, b := range buf[8:n] {
		log.Printf("0x%x ", b)
	}
	log.Println()
	var destAddr [16]byte
	for i, _ := range destAddr {
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

	//log.Println("Injecting decapsulated packet")
	//_, err := conn.WriteTo(buf[8: n], &net.IPAddr{IP: ipHeader.DstIP})
	err := syscall.Sendto(fd6, buf[8:n], 0, &syscall.SockaddrInet6{
		Port:   0,
		ZoneId: 0,
		Addr:   destAddr,
	})
	if err != nil {
		log.Printf("Failed injecting ETR packet: %s.\n", err)
	}
}
