package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ─── Capture session ─────────────────────────────────────────────────────────

// CaptureSession represents an active packet capture goroutine.
type CaptureSession struct {
	cancel context.CancelFunc
}

// Stop cancels the capture goroutine.
func (s *CaptureSession) Stop() { s.cancel() }

// startCapture begins sniffing traffic for targetIP on ifaceName.
// logFn gets text log entries; pktFn receives structured packet events.
func startCapture(ifaceName, targetIP string, logFn func(string), pktFn func(PacketInfo)) (*CaptureSession, error) {
	handle, err := pcapOpenLive(ifaceName, 65536, true, 500*time.Millisecond)
	if err != nil {
		logFn(fmt.Sprintf("Captura raw desativada (%v)", err))
		return nil, err
	}

	filter := fmt.Sprintf("host %s and not arp", targetIP)
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("BPF filter error: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		defer handle.Close()
		packetsChan := handle.Packets()
		logFn(fmt.Sprintf("Capturando %s | filter: %s", targetIP, filter))

		for {
			select {
			case <-ctx.Done():
				logFn("Captura finalizada")
				return
			case pkt, ok := <-packetsChan:
				if !ok {
					return
				}
				info := extractPacketInfo(pkt, targetIP)
				if info == nil {
					continue
				}
				pktFn(*info)
				logFn(fmt.Sprintf("[%s] %s %s:%d → %s:%d  %s",
					info.Protocol, info.Direction,
					info.SrcIP, info.SrcPort,
					info.DstIP, info.DstPort,
					info.Info))
			}
		}
	}()

	return &CaptureSession{cancel: cancel}, nil
}

// ─── Packet analysis ──────────────────────────────────────────────────────────

func extractPacketInfo(pkt gopacket.Packet, targetIP string) *PacketInfo {
	if pkt.NetworkLayer() == nil {
		return nil
	}

	nf := pkt.NetworkLayer().NetworkFlow()
	srcIP := nf.Src().String()
	dstIP := nf.Dst().String()

	dir := "⇄"
	if srcIP == targetIP {
		dir = "↑"
	} else if dstIP == targetIP {
		dir = "↓"
	}

	info := &PacketInfo{
		Time:      time.Now().Format("15:04:05.000"),
		SrcIP:     srcIP,
		DstIP:     dstIP,
		Size:      len(pkt.Data()),
		Direction: dir,
		Protocol:  "IP",
	}

	if tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		info.SrcPort = int(tcp.SrcPort)
		info.DstPort = int(tcp.DstPort)
		info.Protocol = "TCP"

		switch {
		case tcp.DstPort == 80 || tcp.SrcPort == 80:
			info.Protocol = "HTTP"
			info.Info = parseHTTPLine(tcp.Payload)
		case tcp.DstPort == 443 || tcp.SrcPort == 443:
			info.Protocol = "HTTPS"
			if sni := extractSNI(tcp.Payload); sni != "" {
				info.Info = "SNI: " + sni
			}
		case tcp.DstPort == 22 || tcp.SrcPort == 22:
			info.Protocol = "SSH"
		case tcp.DstPort == 21 || tcp.SrcPort == 21:
			info.Protocol = "FTP"
		case tcp.DstPort == 25 || tcp.SrcPort == 25:
			info.Protocol = "SMTP"
		case tcp.DstPort == 143 || tcp.SrcPort == 143:
			info.Protocol = "IMAP"
		case tcp.DstPort == 110 || tcp.SrcPort == 110:
			info.Protocol = "POP3"
		default:
			info.Info = tcpFlagsStr(tcp)
		}
		return info
	}

	if udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		info.SrcPort = int(udp.SrcPort)
		info.DstPort = int(udp.DstPort)
		info.Protocol = "UDP"

		if udp.DstPort == 53 || udp.SrcPort == 53 {
			info.Protocol = "DNS"
			if dns, ok := pkt.Layer(layers.LayerTypeDNS).(*layers.DNS); ok {
				var parts []string
				for _, q := range dns.Questions {
					parts = append(parts, string(q.Name))
				}
				for _, a := range dns.Answers {
					if a.IP != nil {
						parts = append(parts, "→"+a.IP.String())
					}
				}
				info.Info = strings.Join(parts, " ")
			}
		} else if udp.DstPort == 67 || udp.DstPort == 68 {
			info.Protocol = "DHCP"
		}
		return info
	}

	if icmp, ok := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); ok {
		info.Protocol = "ICMP"
		info.Info = icmp.TypeCode.String()
		return info
	}

	return info
}

func parseHTTPLine(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	s := string(payload)
	if idx := strings.Index(s, "\r\n"); idx > 0 {
		line := s[:idx]
		if len(line) > 200 {
			line = line[:200]
		}
		return line
	}
	return ""
}

// extractSNI parses the TLS ClientHello and returns the SNI hostname.
func extractSNI(payload []byte) string {
	if len(payload) < 5 || payload[0] != 0x16 {
		return "" // not a TLS handshake record
	}
	offset := 5 // skip TLS record header
	if offset >= len(payload) || payload[offset] != 0x01 {
		return "" // not ClientHello
	}
	offset += 4  // handshake type (1) + length (3)
	offset += 2  // legacy_version
	offset += 32 // random

	if offset >= len(payload) {
		return ""
	}
	sessionLen := int(payload[offset])
	offset += 1 + sessionLen

	if offset+2 > len(payload) {
		return ""
	}
	csLen := int(payload[offset])<<8 | int(payload[offset+1])
	offset += 2 + csLen

	if offset >= len(payload) {
		return ""
	}
	cmLen := int(payload[offset])
	offset += 1 + cmLen

	if offset+2 > len(payload) {
		return ""
	}
	extTotal := int(payload[offset])<<8 | int(payload[offset+1])
	offset += 2
	end := offset + extTotal

	for offset+4 <= end && end <= len(payload) {
		extType := int(payload[offset])<<8 | int(payload[offset+1])
		extLen := int(payload[offset+2])<<8 | int(payload[offset+3])
		offset += 4
		if extType == 0x00 && offset+5 <= len(payload) { // SNI
			nameLen := int(payload[offset+3])<<8 | int(payload[offset+4])
			if offset+5+nameLen <= len(payload) {
				return string(payload[offset+5 : offset+5+nameLen])
			}
		}
		offset += extLen
	}
	return ""
}

func tcpFlagsStr(tcp *layers.TCP) string {
	var b strings.Builder
	if tcp.SYN {
		b.WriteString("SYN ")
	}
	if tcp.ACK {
		b.WriteString("ACK ")
	}
	if tcp.FIN {
		b.WriteString("FIN ")
	}
	if tcp.RST {
		b.WriteString("RST ")
	}
	if tcp.PSH {
		b.WriteString("PSH ")
	}
	return strings.TrimSpace(b.String())
}

// ─── IP forwarding ────────────────────────────────────────────────────────────

func enableForwarding() {
	// netsh approach (no reboot required on current kernel)
	exec.Command("netsh", "interface", "ipv4", "set", "global", "forwarding=enabled").Run() //nolint:errcheck
	// Registry for session persistence
	exec.Command("reg", "add", //nolint:errcheck
		`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
		"/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "1", "/f",
	).Run()
}

func disableForwarding() {
	exec.Command("netsh", "interface", "ipv4", "set", "global", "forwarding=disabled").Run() //nolint:errcheck
	exec.Command("reg", "add", //nolint:errcheck
		`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
		"/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "0", "/f",
	).Run()
}

// getDefaultGateway attempts to read the default gateway on Windows, Linux, and Android.
func getDefaultGateway() string {
	// 1. Windows: route print
	if out, err := exec.Command("route", "print", "0.0.0.0").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
				return fields[2]
			}
		}
	}

	// 2. Linux / Android: /proc/net/route
	if out, err := exec.Command("cat", "/proc/net/route").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[1] == "00000000" {
				gwHex := fields[2]
				if len(gwHex) == 8 {
					var b0, b1, b2, b3 byte
					fmt.Sscanf(gwHex, "%02x%02x%02x%02x", &b3, &b2, &b1, &b0)
					return fmt.Sprintf("%d.%d.%d.%d", b0, b1, b2, b3)
				}
			}
		}
	}

	// 3. Linux / Android fallback: ip route
	if out, err := exec.Command("ip", "route").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "default via ") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					return parts[2]
				}
			}
		}
	}

	return ""
}
