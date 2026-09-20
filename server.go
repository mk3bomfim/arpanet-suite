package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// startServer wires up all routes and starts listening on the given port.
func startServer(port int, static fs.FS) error {
	mux := http.NewServeMux()

	// ── API endpoints ─────────────────────────────────────────────────────────
	mux.HandleFunc("/api/interfaces", withCORS(handleInterfaces))
	mux.HandleFunc("/api/localinfo", withCORS(handleLocalInfo))
	mux.HandleFunc("/api/scan", withCORS(handleScan))
	mux.HandleFunc("/api/spoof/start", withCORS(handleSpoofStart))
	mux.HandleFunc("/api/spoof/stop", withCORS(handleSpoofStop))
	mux.HandleFunc("/api/dos/start", withCORS(handleDosStart))
	mux.HandleFunc("/api/dos/stop", withCORS(handleDosStop))
	mux.HandleFunc("/api/killall/start", withCORS(handleKillAllStart))
	mux.HandleFunc("/api/killall/stop", withCORS(handleKillAllStop))
	mux.HandleFunc("/api/capture/start", withCORS(handleCaptureStart))
	mux.HandleFunc("/api/capture/stop", withCORS(handleCaptureStop))
	mux.HandleFunc("/api/gateway", withCORS(handleGateway))

	// ── SSE streams ───────────────────────────────────────────────────────────
	mux.HandleFunc("/api/logs", handleLogStream)
	mux.HandleFunc("/api/logs/stream", handleLogStream)
	mux.HandleFunc("/api/packets", handlePacketStream)
	mux.HandleFunc("/api/packets/stream", handlePacketStream)

	// ── Static UI ─────────────────────────────────────────────────────────────
	mux.Handle("/", http.FileServer(http.FS(static)))

	return http.ListenAndServe(fmt.Sprintf(":%d", port), mux)
}

// ─── Middleware ───────────────────────────────────────────────────────────────

func withCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			return
		}
		h(w, r)
	}
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

func handleInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := listInterfaces()
	if err != nil {
		jsonErr(w, err.Error(), 500)
		return
	}
	jsonOK(w, ifaces)
}

func handleLocalInfo(w http.ResponseWriter, r *http.Request) {
	iface := r.URL.Query().Get("iface")
	if iface == "" {
		jsonErr(w, "missing iface", 400)
		return
	}
	ip, mac, cidr, err := getLocalInfo(iface)
	if err != nil {
		jsonErr(w, err.Error(), 500)
		return
	}
	gw := getDefaultGateway()
	jsonOK(w, map[string]string{
		"ip":   ip.String(),
		"mac":  mac.String(),
		"cidr": cidr,
		"gw":   gw,
	})
}

func handleGateway(w http.ResponseWriter, r *http.Request) {
	gw := getDefaultGateway()
	jsonOK(w, map[string]string{"gateway": gw})
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, "POST only", 405)
		return
	}
	var req struct {
		Iface string `json:"iface"`
		CIDR  string `json:"cidr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Iface == "" || req.CIDR == "" {
		jsonErr(w, "invalid body: need iface + cidr", 400)
		return
	}

	app.mu.Lock()
	app.selectedIface = req.Iface
	app.mu.Unlock()

	logFn := func(msg string) { app.logInfo("scan", msg) }

	hosts, err := scanNetwork(req.Iface, req.CIDR, logFn)
	if err != nil {
		app.logError("scan", err.Error())
		jsonErr(w, err.Error(), 500)
		return
	}

	app.mu.Lock()
	app.hosts = hosts
	app.mu.Unlock()

	jsonOK(w, hosts)
}

func handleSpoofStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Iface     string `json:"iface"`
		TargetIP  string `json:"target_ip"`
		GatewayIP string `json:"gateway_ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid body", 400)
		return
	}
	if req.Iface == "" || req.TargetIP == "" || req.GatewayIP == "" {
		jsonErr(w, "need iface, target_ip, gateway_ip", 400)
		return
	}

	logFn := func(msg string) { app.logInfo("mitm", msg) }
	sess, err := startSpoof(req.Iface, req.TargetIP, req.GatewayIP, true, logFn)
	if err != nil {
		app.logError("mitm", err.Error())
		jsonErr(w, err.Error(), 500)
		return
	}

	// Also start capture so traffic tab populates
	capFn := func(p PacketInfo) {
		atomic.AddInt64(&app.pktCount, 1)
		app.packets.Emit(p)
	}
	cap, _ := startCapture(req.Iface, req.TargetIP, logFn, capFn)

	app.mu.Lock()
	app.spoofSessions = append(app.spoofSessions, sess)
	app.capSession = cap
	app.gatewayIP = req.GatewayIP
	app.mu.Unlock()

	jsonOK(w, map[string]string{"status": "started", "mode": "mitm"})
}

func handleSpoofStop(w http.ResponseWriter, r *http.Request) {
	app.mu.Lock()
	sessions := app.spoofSessions
	cap := app.capSession
	app.spoofSessions = nil
	app.capSession = nil
	app.mu.Unlock()

	for _, s := range sessions {
		s.Stop()
	}
	if cap != nil {
		cap.Stop()
	}
	jsonOK(w, map[string]string{"status": "stopped"})
}

func handleDosStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Iface     string `json:"iface"`
		TargetIP  string `json:"target_ip"`
		GatewayIP string `json:"gateway_ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid body", 400)
		return
	}

	logFn := func(msg string) { app.logInfo("dos", msg) }
	sess, err := startSpoof(req.Iface, req.TargetIP, req.GatewayIP, false, logFn)
	if err != nil {
		app.logError("dos", err.Error())
		jsonErr(w, err.Error(), 500)
		return
	}

	app.mu.Lock()
	app.spoofSessions = append(app.spoofSessions, sess)
	app.mu.Unlock()

	jsonOK(w, map[string]string{"status": "started", "mode": "dos"})
}

func handleDosStop(w http.ResponseWriter, r *http.Request) {
	handleSpoofStop(w, r) // same teardown
}

func handleKillAllStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Iface     string `json:"iface"`
		GatewayIP string `json:"gateway_ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid body", 400)
		return
	}

	app.mu.RLock()
	hosts := app.hosts
	app.mu.RUnlock()

	if len(hosts) == 0 {
		jsonErr(w, "no hosts — run a scan first", 400)
		return
	}

	logFn := func(msg string) { app.logWarn("kill", msg) }
	sessions := killAll(req.Iface, req.GatewayIP, hosts, logFn)

	app.mu.Lock()
	app.killSessions = sessions
	app.mu.Unlock()

	jsonOK(w, map[string]any{"status": "started", "targets": len(sessions)})
}

func handleKillAllStop(w http.ResponseWriter, r *http.Request) {
	app.mu.Lock()
	sessions := app.killSessions
	app.killSessions = nil
	app.mu.Unlock()

	for _, s := range sessions {
		s.Stop()
	}
	app.logInfo("kill", fmt.Sprintf("Kill-all stopped — %d sessions cleaned up", len(sessions)))
	jsonOK(w, map[string]string{"status": "stopped"})
}

func handleCaptureStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Iface    string `json:"iface"`
		TargetIP string `json:"target_ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid body", 400)
		return
	}

	logFn := func(msg string) { app.logInfo("capture", msg) }
	capFn := func(p PacketInfo) {
		atomic.AddInt64(&app.pktCount, 1)
		app.packets.Emit(p)
	}
	sess, err := startCapture(req.Iface, req.TargetIP, logFn, capFn)
	if err != nil {
		jsonErr(w, err.Error(), 500)
		return
	}

	app.mu.Lock()
	if app.capSession != nil {
		app.capSession.Stop()
	}
	app.capSession = sess
	app.mu.Unlock()

	jsonOK(w, map[string]string{"status": "started"})
}

func handleCaptureStop(w http.ResponseWriter, r *http.Request) {
	app.mu.Lock()
	cap := app.capSession
	app.capSession = nil
	app.mu.Unlock()

	if cap != nil {
		cap.Stop()
	}
	jsonOK(w, map[string]string{"status": "stopped"})
}

// ─── SSE streams ──────────────────────────────────────────────────────────────

func handleLogStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", 500)
		return
	}

	ch := app.logs.Subscribe()
	defer app.logs.Unsubscribe(ch)

	// Send a keepalive comment every 15 s so proxies don't time out
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// Greet
	fmt.Fprintf(w, "data: {\"time\":%q,\"level\":\"INFO\",\"source\":\"sys\",\"message\":\"Log stream connected\"}\n\n",
		time.Now().Format("15:04:05.000"))
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case payload, ok := <-ch:
			if !ok {
				return
			}
			w.Write(payload)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func handlePacketStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", 500)
		return
	}

	ch := app.packets.Subscribe()
	defer app.packets.Unsubscribe(ch)

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case payload, ok := <-ch:
			if !ok {
				return
			}
			w.Write(payload)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

// ─── Utilities ────────────────────────────────────────────────────────────────

// formatSSE wraps a JSON object in an SSE data line.
func formatSSE(jsonStr string) string {
	return "data: " + strings.TrimSpace(jsonStr) + "\n\n"
}
