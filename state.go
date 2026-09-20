package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
)

// ─── Shared types ────────────────────────────────────────────────────────────

type packetHandle interface {
	Close()
	WritePacketData(data []byte) error
	SetBPFFilter(filter string) error
	Packets() <-chan gopacket.Packet
}

// Host represents a discovered network device.
type Host struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Hostname string `json:"hostname"`
}

// Iface is a network interface advertised to the frontend.
type Iface struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Addresses   []string `json:"addresses"`
}

// LogEntry is a structured log event.
type LogEntry struct {
	Time    string `json:"time"`
	Level   string `json:"level"`   // INFO | WARN | ERROR | PACKET
	Source  string `json:"source"`  // arp | mitm | scan | sys
	Message string `json:"message"`
}

// PacketInfo carries captured packet metadata for the Traffic tab.
type PacketInfo struct {
	Time      string `json:"time"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   int    `json:"src_port"`
	DstPort   int    `json:"dst_port"`
	Protocol  string `json:"protocol"`
	Info      string `json:"info"`
	Size      int    `json:"size"`
	Direction string `json:"direction"`
}

// ─── Log Hub ─────────────────────────────────────────────────────────────────

// LogHub broadcasts log entries to all connected SSE clients.
type LogHub struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}
}

func newLogHub() *LogHub {
	return &LogHub{clients: make(map[chan []byte]struct{})}
}

func (h *LogHub) Subscribe() chan []byte {
	ch := make(chan []byte, 256)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *LogHub) Unsubscribe(ch chan []byte) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
	close(ch)
}

func (h *LogHub) Emit(level, source, msg string) {
	entry := fmt.Sprintf(`{"time":%q,"level":%q,"source":%q,"message":%q}`,
		time.Now().Format("15:04:05.000"), level, source, msg)
	payload := []byte("data: " + entry + "\n\n")
	h.mu.Lock()
	for ch := range h.clients {
		select {
		case ch <- payload:
		default: // slow client — drop
		}
	}
	h.mu.Unlock()
}

// ─── Packet Hub ───────────────────────────────────────────────────────────────

// PacketHub broadcasts captured packet info to all Traffic-tab SSE clients.
type PacketHub struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}
}

func newPacketHub() *PacketHub {
	return &PacketHub{clients: make(map[chan []byte]struct{})}
}

func (h *PacketHub) Subscribe() chan []byte {
	ch := make(chan []byte, 512)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *PacketHub) Unsubscribe(ch chan []byte) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
	close(ch)
}

func (h *PacketHub) Emit(p PacketInfo) {
	payload := []byte(fmt.Sprintf(
		"data: {\"time\":%q,\"src_ip\":%q,\"dst_ip\":%q,\"src_port\":%d,\"dst_port\":%d,\"protocol\":%q,\"info\":%q,\"size\":%d,\"direction\":%q}\n\n",
		p.Time, p.SrcIP, p.DstIP, p.SrcPort, p.DstPort, p.Protocol, p.Info, p.Size, p.Direction,
	))
	h.mu.Lock()
	for ch := range h.clients {
		select {
		case ch <- payload:
		default:
		}
	}
	h.mu.Unlock()
}

// ─── App State ────────────────────────────────────────────────────────────────

// AppState holds all mutable runtime state. All access must hold mu.
type AppState struct {
	mu sync.RWMutex

	selectedIface string
	gatewayIP     string
	hosts         []Host

	// Active sessions
	spoofSessions []*SpoofSession
	capSession    *CaptureSession
	killSessions  []*SpoofSession

	// Hubs
	logs    *LogHub
	packets *PacketHub

	// Counters
	pktCount int64
}

// global singleton
var app = &AppState{
	logs:    newLogHub(),
	packets: newPacketHub(),
}

// log emits a log entry and prints it to stdout.
func (s *AppState) log(level, source, msg string) {
	fmt.Printf("[%s][%s] %s\n", level, source, msg)
	s.logs.Emit(level, source, msg)
}

func (s *AppState) logInfo(source, msg string)  { s.log("INFO", source, msg) }
func (s *AppState) logWarn(source, msg string)  { s.log("WARN", source, msg) }
func (s *AppState) logError(source, msg string) { s.log("ERROR", source, msg) }
