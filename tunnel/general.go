package tunnel

import "net"

type Tunnel interface {
	Name() string
	Read(packet []byte) (int, error)
	Write(packet []byte) (int, error)
	IP() net.IP
	Netmask() net.IPMask
	MTU() int
	SetIP(ip net.IP, netmask net.IPMask) error
	Up() error
	Down() error
	Close() error
	IsRunning() bool
	Stats() (*TunnelStats, error)
}

type TunnelStats struct {
	RXBytes   uint64
	RXPackets uint64
	TXBytes   uint64
	TXPackets uint64
	LastError error
}
