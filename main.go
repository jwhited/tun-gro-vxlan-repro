package main

import (
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	writeSingleFlagName         = "write-single"
	writeCoalescedFlagName      = "write-coalesced"
	writeSingleVxlanFlagName    = "write-single-vxlan"
	writeCoalescedVxlanFlagName = "write-coalesced-vxlan"
)

var (
	flagTunName             = flag.String("tun-name", "tun0", "name of TUN device")
	flagTunAddr             = flag.String("tun-addr", "172.16.0.1/24", "TUN device L3 addr")
	flagVxlanName           = flag.String("vxlan-name", "vxlan0", "name of vxlan device")
	flagVxlanAddr           = flag.String("vxlan-addr", "172.16.77.1/24", "vxlan device L3 addr")
	flagVxvlanVNI           = flag.Int("vxlan-vni", 100, "vxlan vni")
	flagWriteSingle         = flag.Bool(writeSingleFlagName, false, "write single packet TUN->UDP socket")
	flagWriteCoalesced      = flag.Bool(writeCoalescedFlagName, false, "write coalesced packets TUN->UDP socket")
	flagWriteSingleVxlan    = flag.Bool(writeSingleVxlanFlagName, false, "write single packet TUN->VXLAN->UDP socket")
	flagWriteCoalescedVxlan = flag.Bool(writeCoalescedVxlanFlagName, false, "write coalesced packets TUN->VXLAN->UDP socket")
)

// checksum returns the RFC 1071 checksum of b
func checksum(b []byte, initial uint16) uint16 {
	var ac uint32
	ac += uint32(initial)
	i := 0
	n := len(b)
	for n >= 2 {
		ac += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		n -= 2
		i += 2
	}
	if n == 1 {
		ac += uint32(b[i]) << 8
	}
	for (ac >> 16) > 0 {
		ac = (ac >> 16) + (ac & 0xffff)
	}
	return uint16(ac)
}

// udpPsuedoChecksum returns the RFC 1071 pseudo header checksum of a UDP packet
// with src, dst, and dataLen.
func udpPsuedoChecksum(src, dst net.IP, dataLen int) uint16 {
	pseudo := make([]byte, 12)
	copy(pseudo, src)
	copy(pseudo[4:], dst)
	pseudo[9] = 17 // protocol UDP
	binary.BigEndian.PutUint16(pseudo[10:], uint16(dataLen))
	return checksum(pseudo, 0)
}

// udpChecksum returns the RFC 1071 checksum of a UDP packet with src, dst, and
// bytes b beginning at the UDP header.
func udpChecksum(src, dst net.IP, b []byte) uint16 {
	pseudo := udpPsuedoChecksum(src, dst, len(b))
	return checksum(b, pseudo)
}

const virtioNetHdrLen = int(unsafe.Sizeof(virtioNetHdr{}))

type virtioNetHdr struct {
	flags      uint8
	gsoType    uint8
	hdrLen     uint16
	gsoSize    uint16
	csumStart  uint16
	csumOffset uint16
}

func (v *virtioNetHdr) encode(b []byte) error {
	if len(b) < virtioNetHdrLen {
		return io.ErrShortBuffer
	}
	copy(b[:virtioNetHdrLen], unsafe.Slice((*byte)(unsafe.Pointer(v)), virtioNetHdrLen))
	return nil
}

// getIPv4Header returns an ipv4 header with src, dst, and protocol UDP. Total
// length and checksum are unset (0).
func getIPv4Header(src, dst net.IP) []byte {
	ipH := make([]byte, 20)
	ipH[0] = 0x45 // version 4, header length 20 bytes
	ipH[8] = 64   // TTL
	ipH[9] = 17   // protocol UDP
	copy(ipH[12:16], src)
	copy(ipH[16:20], dst)
	return ipH
}

// getUDPHeader returns a UDP header with srcPort, dstPort, and length. Checksum
// is unset (0).
func getUDPHeader(srcPort, dstPort uint16, length uint16) []byte {
	udpH := make([]byte, 8)
	binary.BigEndian.PutUint16(udpH[:2], srcPort)
	binary.BigEndian.PutUint16(udpH[2:4], dstPort)
	binary.BigEndian.PutUint16(udpH[4:6], length)
	return udpH
}

// setupTUN creates a TUN interface, writable via file. It can be cleaned up by
// calling the returned closure cleanup.
func setupTUN() (file *os.File, cleanup func()) {
	nfd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		log.Panic(err)
	}

	ifr, err := unix.NewIfreq(*flagTunName)
	if err != nil {
		unix.Close(nfd)
		log.Panic(err)
	}

	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
	err = unix.IoctlIfreq(nfd, unix.TUNSETIFF, ifr)
	if err != nil {
		unix.Close(nfd)
		log.Panic(err)
	}

	err = unix.SetNonblock(nfd, true)
	if err != nil {
		unix.Close(nfd)
		log.Panic(err)
	}

	err = unix.IoctlSetInt(nfd, unix.TUNSETOFFLOAD, unix.TUN_F_CSUM|unix.TUN_F_USO4|unix.TUN_F_USO6)
	if err != nil {
		unix.Close(nfd)
		log.Panic(err)
	}

	file = os.NewFile(uintptr(nfd), "/dev/net/tun")

	cmd := exec.Command("/usr/sbin/ip", "addr", "add", *flagTunAddr, "dev", *flagTunName)
	err = cmd.Run()
	if err != nil {
		file.Close()
		unix.Close(nfd)
		log.Panic(err)
	}

	cmd = exec.Command("/usr/sbin/ip", "link", "set", *flagTunName, "up")
	err = cmd.Run()
	if err != nil {
		file.Close()
		unix.Close(nfd)
		log.Panic(err)
	}

	cleanup = func() {
		file.Close()
		unix.Close(nfd)
	}

	return file, cleanup
}

// setupVxlan creates a vxlan interface, returning its ethernet addr and a
// closure that can be used to clean it up.
func setupVxlan() (ethAddr net.HardwareAddr, cleanup func()) {
	cmd := exec.Command("/usr/sbin/ip", "link", "add", *flagVxlanName, "type", "vxlan", "id", strconv.Itoa(*flagVxvlanVNI))
	err := cmd.Run()
	if err != nil {
		log.Panic(err)
	}

	cleanup = func() {
		exec.Command("/usr/sbin/ip", "link", "del", *flagVxlanName).Run()
	}

	cmd = exec.Command("/usr/sbin/ip", "addr", "add", *flagVxlanAddr, "dev", *flagVxlanName)
	err = cmd.Run()
	if err != nil {
		cleanup()
		log.Panic(err)
	}

	cmd = exec.Command("/usr/sbin/ip", "link", "set", *flagVxlanName, "up")
	err = cmd.Run()
	if err != nil {
		cleanup()
		log.Panic(err)
	}

	cmd = exec.Command("/usr/sbin/ip", "link", "show", *flagVxlanName)
	out, err := cmd.Output()
	if err != nil {
		cleanup()
		log.Panic(err)
	}

	split := strings.Split(string(out), " ")
	for i, s := range split {
		if strings.Contains(s, "ether") && len(split) > i+2 {
			ethAddr, err = net.ParseMAC(split[i+1])
			if err != nil {
				cleanup()
				log.Panic(err)
			}
			break
		}
	}

	return ethAddr, cleanup
}

// packet offsets
const (
	outerUdphAt = 20
	vxlanhAt    = outerUdphAt + 8
	innerIphAt  = vxlanhAt + 8 + 14
	innerUdphAt = innerIphAt + 20
)

func getVxlanEncapsulatedUDP(vxlanEthAddr net.HardwareAddr, outerSrcIP, outerDstIP, innerSrcIP, innerDstIP net.IP, outerDstPort uint16) []byte {
	// ip header
	outerIpH := getIPv4Header(outerSrcIP, outerDstIP)

	// udp header
	outerUdpH := getUDPHeader(7777, outerDstPort, 8+8+14+20+8+1)

	// vxlan header
	vxlanH := make([]byte, 8)
	vxlanH[0] = 0x08                                    // vni=true in flags
	binary.BigEndian.PutUint32(vxlanH[3:], uint32(100)) // vni

	// ethernet header
	ethH := make([]byte, 14)
	copy(ethH, vxlanEthAddr) // dst addr
	ethH[7] = 0x01           // src addr
	ethH[12] = 0x08          // protocol ipv4

	innerIpH := getIPv4Header(innerSrcIP, innerDstIP)
	innerUdpH := getUDPHeader(7777, 7777, 8+1)

	packet := make([]byte, 0)
	packet = append(packet, outerIpH...)
	packet = append(packet, outerUdpH...)
	packet = append(packet, vxlanH...)
	packet = append(packet, ethH...)
	packet = append(packet, innerIpH...)
	packet = append(packet, innerUdpH...)
	packet = append(packet, 0x01) // signal this IS NOT part of a coalesced group

	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))                         // outer iph total len
	binary.BigEndian.PutUint16(packet[innerIphAt+2:], uint16(len(packet[innerIphAt:]))) // inner iph total len

	binary.BigEndian.PutUint16(packet[10:12], ^checksum(packet[:20], 0))                                            // outer iph checksum
	binary.BigEndian.PutUint16(packet[innerIphAt+10:innerIphAt+12], ^checksum(packet[innerIphAt:innerIphAt+20], 0)) // inner iph checksum

	binary.BigEndian.PutUint16(packet[innerUdphAt+6:], ^udpChecksum(innerSrcIP, innerDstIP, packet[innerUdphAt:])) // inner udph checksum
	binary.BigEndian.PutUint16(packet[outerUdphAt+6:], ^udpChecksum(outerSrcIP, outerDstIP, packet[outerUdphAt:])) // outer udph checksum

	withVirtioHdr := make([]byte, virtioNetHdrLen+len(packet))
	copy(withVirtioHdr[virtioNetHdrLen:], packet)

	return withVirtioHdr
}

func getCoalescedVxlanEncapsulatedUDP(first []byte, outerSrcIP, outerDstIP, innerSrcIP, innerDstIP net.IP) []byte {
	packetsCoalesced := make([]byte, len(first))
	copy(packetsCoalesced, first)
	packetsCoalesced[len(packetsCoalesced)-1] = 0x02 // signal this IS part of a coalesced group

	// update inner udph checksum
	packetsCoalesced[innerUdphAt+6] = 0
	packetsCoalesced[innerUdphAt+7] = 0
	binary.BigEndian.PutUint16(packetsCoalesced[innerUdphAt+6:], ^udpChecksum(innerSrcIP, innerDstIP, packetsCoalesced[innerUdphAt:]))

	// append duplicate packet from vxlan header down, inclusive
	packetsCoalesced = append(packetsCoalesced, packetsCoalesced[vxlanhAt:]...)

	binary.BigEndian.PutUint16(packetsCoalesced[2:], uint16(len(packetsCoalesced))) // update outer iph total len
	packetsCoalesced[10] = 0
	packetsCoalesced[11] = 0
	binary.BigEndian.PutUint16(packetsCoalesced[10:12], ^checksum(packetsCoalesced[:20], 0))                  // update outer iph checksum
	binary.BigEndian.PutUint16(packetsCoalesced[outerUdphAt+4:], uint16(len(packetsCoalesced[outerUdphAt:]))) // update outer udph len
	packetsCoalesced[outerUdphAt+6] = 0
	packetsCoalesced[outerUdphAt+7] = 0
	binary.BigEndian.PutUint16(packetsCoalesced[outerUdphAt+6:], udpPsuedoChecksum(outerSrcIP, outerDstIP, len(packetsCoalesced[outerUdphAt:]))) // update outer udph checksum (partial, just pseudo header)

	withVirtioHdr := make([]byte, virtioNetHdrLen+len(packetsCoalesced))
	copy(withVirtioHdr[virtioNetHdrLen:], packetsCoalesced)
	v := virtioNetHdr{
		flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
		gsoType:    unix.VIRTIO_NET_HDR_GSO_UDP_L4,
		hdrLen:     20 + 8,
		gsoSize:    uint16(len(first[vxlanhAt:])),
		csumStart:  20,
		csumOffset: 6,
	}
	err := v.encode(withVirtioHdr)
	if err != nil {
		log.Panic(err)
	}
	return withVirtioHdr
}

func main() {
	flag.Parse()

	if !*flagWriteSingle && !*flagWriteCoalesced && !*flagWriteSingleVxlan && !*flagWriteCoalescedVxlan {
		log.Panicf("nothing to test, specify at least one of: %v", []string{
			writeSingleFlagName,
			writeCoalescedFlagName,
			writeSingleVxlanFlagName,
			writeCoalescedVxlanFlagName,
		})
	}

	file, tunCleanup := setupTUN()
	defer tunCleanup()

	vxlanEthAddr, vxlanCleanup := setupVxlan()
	defer vxlanCleanup()

	vxlanIP, _, err := net.ParseCIDR(*flagVxlanAddr)
	if err != nil {
		log.Panic(err)
	}
	vxlanIP = vxlanIP.To4()

	tunIP, _, err := net.ParseCIDR(*flagTunAddr)
	if err != nil {
		log.Panic(err)
	}
	tunIP = tunIP.To4()
	outerSrcIP := make([]byte, 4)
	binary.BigEndian.PutUint32(outerSrcIP, binary.BigEndian.Uint32(tunIP)+1)

	const (
		udpListenPort         = 7777
		linuxDefaultVxlanPort = 8472
	)

	// bind UDP socket, read datagrams, and print them
	uc, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: udpListenPort,
	})
	if err != nil {
		log.Panic(err)
	}
	go func() {
		for {
			b := make([]byte, 1000)
			n, err := uc.Read(b)
			if err != nil {
				log.Panic(err)
			}
			log.Printf("read %d bytes, val: %x", n, b[:n])
		}
	}()

	innerSrcIP := make([]byte, 4)
	binary.BigEndian.PutUint32(innerSrcIP, binary.BigEndian.Uint32(vxlanIP)+1)

	// craft packets for each mode
	singlePacketDstVxlanPort := getVxlanEncapsulatedUDP(vxlanEthAddr, outerSrcIP, tunIP, innerSrcIP, vxlanIP, linuxDefaultVxlanPort)
	coalescedPacketsDstVxlanPort := getCoalescedVxlanEncapsulatedUDP(singlePacketDstVxlanPort[virtioNetHdrLen:], outerSrcIP, tunIP, innerSrcIP, vxlanIP)
	singlePacketDstDirect := getVxlanEncapsulatedUDP(vxlanEthAddr, outerSrcIP, tunIP, innerSrcIP, vxlanIP, udpListenPort)
	coalescedPacketsDstDirect := getCoalescedVxlanEncapsulatedUDP(singlePacketDstDirect[virtioNetHdrLen:], outerSrcIP, tunIP, innerSrcIP, vxlanIP)

	// write packets to TUN
	ticker := time.NewTicker(time.Second)
	go func() {
		for {
			<-ticker.C

			if *flagWriteSingle {
				_, err = file.Write(singlePacketDstDirect)
				if err != nil {
					log.Panic(err)
				}
			}

			if *flagWriteCoalesced {
				_, err = file.Write(coalescedPacketsDstDirect)
				if err != nil {
					log.Panic(err)
				}
			}

			if *flagWriteSingleVxlan {
				_, err = file.Write(singlePacketDstVxlanPort)
				if err != nil {
					log.Panic(err)
				}
			}

			if *flagWriteCoalescedVxlan {
				_, err = file.Write(coalescedPacketsDstVxlanPort)
				if err != nil {
					log.Panic(err)
				}
			}
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	<-sigCh
}
