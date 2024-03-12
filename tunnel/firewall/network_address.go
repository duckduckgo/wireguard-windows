package firewall

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
)

type networkAddress struct {
	ip   string
	mask string
}

func (addr *networkAddress) cidr() string {
	mask := net.IPMask(net.ParseIP(addr.mask).To4())
	prefixSize, _ := mask.Size()

	return fmt.Sprint(addr.ip, "/", prefixSize)
}

func (addr *networkAddress) wtFwpV4AddrAndMask() wtFwpV4AddrAndMask {
	return wtFwpV4AddrAndMask{
		addr: ipV4ToUint32(addr.ip),
		mask: ipV4ToUint32(addr.mask),
	}
}

func ipV4ToUint32(ip string) uint32 {
	addr := netip.MustParseAddr(ip).As4()
	return binary.BigEndian.Uint32(addr[:])
}
