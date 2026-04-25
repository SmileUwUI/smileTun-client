package tunnel

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"

	"github.com/songgao/water"
)

type LinuxTunnel struct {
	iface    *water.Interface
	name     string
	ip       net.IP
	netmask  net.IPMask
	mtu      int
	running  bool
	mu       sync.RWMutex
	stats    TunnelStats
	oldGW    string
	oldIface string
}

func NewTunnel(name string, mtu int, address net.IP, netmask net.IPMask) (Tunnel, error) {
	waterConfig := water.Config{
		DeviceType: water.TUN,
	}

	if name != "" {
		waterConfig.Name = name
	}

	iface, err := water.New(waterConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN: %w", err)
	}

	tunnel := &LinuxTunnel{
		iface:   iface,
		name:    iface.Name(),
		mtu:     mtu,
		running: false,
	}

	if address != nil {
		if err := tunnel.SetIP(address, netmask); err != nil {
			return nil, err
		}
	}

	if mtu > 0 {
		tunnel.SetMTU(mtu)
	}

	return tunnel, nil
}

func (t *LinuxTunnel) Name() string {
	return t.name
}

func (t *LinuxTunnel) Read(packet []byte) (int, error) {
	return t.iface.Read(packet)
}

func (t *LinuxTunnel) Write(packet []byte) (int, error) {
	return t.iface.Write(packet)
}

func (t *LinuxTunnel) IP() net.IP {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.ip
}

func (t *LinuxTunnel) Netmask() net.IPMask {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.netmask
}

func (t *LinuxTunnel) MTU() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.mtu
}

func (t *LinuxTunnel) SetIP(ip net.IP, netmask net.IPMask) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.ip != nil {
		exec.Command("ip", "addr", "del",
			fmt.Sprintf("%s/%d", t.ip, t.getPrefixLen()),
			"dev", t.name).Run()
	}

	prefixLen, _ := netmask.Size()
	cmd := exec.Command("ip", "addr", "add",
		fmt.Sprintf("%s/%d", ip.String(), prefixLen),
		"dev", t.name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set IP: %w", err)
	}

	t.ip = ip
	t.netmask = netmask
	return nil
}

func (t *LinuxTunnel) SetMTU(mtu int) error {
	cmd := exec.Command("ip", "link", "set", "dev", t.name, "mtu", fmt.Sprintf("%d", mtu))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}
	t.mtu = mtu
	return nil
}

func (t *LinuxTunnel) saveDefaultRoute() error {
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	parts := strings.Fields(string(output))
	for i, part := range parts {
		if part == "via" && i+1 < len(parts) {
			t.oldGW = parts[i+1]
		}
		if part == "dev" && i+1 < len(parts) {
			t.oldIface = parts[i+1]
		}
	}

	return nil
}

func (t *LinuxTunnel) restoreDefaultRoute() error {
	exec.Command("ip", "route", "del", "default").Run()

	if t.oldGW != "" && t.oldIface != "" {
		cmd := exec.Command("ip", "route", "add", "default", "via", t.oldGW, "dev", t.oldIface)
		return cmd.Run()
	}

	return nil
}

func (t *LinuxTunnel) SetupDefaultRoute() error {
	if err := t.saveDefaultRoute(); err != nil {
		return err
	}

	exec.Command("ip", "route", "del", "default").Run()

	cmd := exec.Command("ip", "route", "add", "default", "dev", t.name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set default route to TUN: %w", err)
	}

	fmt.Printf("Default route changed to dev %s\n", t.name)
	return nil
}

func (t *LinuxTunnel) AddRoutes(routes []*net.IPNet) error {
	for _, route := range routes {
		if route == nil {
			continue
		}

		exec.Command("ip", "route", "del", route.String()).Run()

		cmd := exec.Command("ip", "route", "add", route.String(), "dev", t.name)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add route %s: %w", route.String(), err)
		}

		fmt.Printf("Route added: %s dev %s\n", route.String(), t.name)
	}
	return nil
}

func (t *LinuxTunnel) DeleteRoutes(routes []*net.IPNet) error {
	for _, route := range routes {
		if route == nil {
			continue
		}

		exec.Command("ip", "route", "del", route.String(), "dev", t.name).Run()
	}
	return nil
}

func (t *LinuxTunnel) Up() error {
	cmd := exec.Command("ip", "link", "set", "dev", t.name, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring up interface: %w", err)
	}

	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

	if err := t.SetupDefaultRoute(); err != nil {
		return err
	}

	t.running = true
	fmt.Printf("TUN interface %s is UP with IP %s\n", t.name, t.ip)
	return nil
}

func (t *LinuxTunnel) Down() error {
	t.restoreDefaultRoute()

	cmd := exec.Command("ip", "link", "set", "dev", t.name, "down")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring down interface: %w", err)
	}

	t.running = false
	fmt.Printf("TUN interface %s is DOWN, routes restored\n", t.name)
	return nil
}

func (t *LinuxTunnel) Close() error {
	t.Down()
	return t.iface.Close()
}

func (t *LinuxTunnel) IsRunning() bool {
	return t.running
}

func (t *LinuxTunnel) Stats() (*TunnelStats, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	stats := &TunnelStats{
		RXBytes:   t.stats.RXBytes,
		RXPackets: t.stats.RXPackets,
		TXBytes:   t.stats.TXBytes,
		TXPackets: t.stats.TXPackets,
	}

	return stats, nil
}

func (t *LinuxTunnel) getPrefixLen() int {
	if t.netmask == nil {
		return 24
	}
	len, _ := t.netmask.Size()
	return len
}
