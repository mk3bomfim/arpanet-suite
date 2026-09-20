# NetPhantom — ARP Spoof Suite (Go + WebView2)

Ferramenta de auditoria de rede com interface gráfica web embutida. Usa `gopacket` + Npcap para operações Layer 2, e `go-webview2` para a GUI. Backend Go expõe uma API HTTP local; frontend HTML/CSS/JS consome via fetch + SSE para logs em tempo real.

---

## ⚠️ Pré-requisitos do Sistema

> [!IMPORTANT]
> O usuário precisa ter instalado antes de rodar:
> 1. **Npcap** — https://nmap.org/npcap/ (modo WinPcap compat habilitado)
> 2. **MinGW-w64** — para compilar o CGO do gopacket no Windows
> 3. **Go 1.22+**
> 4. **WebView2 Runtime** — já vem no Windows 10/11 moderno

---

## Arquitetura

```
netphantom/
├── main.go              — entry point, abre webview + inicia servidor HTTP
├── go.mod
├── internal/
│   ├── server/
│   │   └── server.go    — HTTP API + SSE log stream
│   ├── arp/
│   │   ├── scanner.go   — scan de rede (ARP ping sweep)
│   │   ├── spoof.go     — engine de ARP spoofing (loop de envio)
│   │   └── dos.go       — modo DoS (não re-encaminha pacotes)
│   ├── mitm/
│   │   └── mitm.go      — IP forwarding + captura de tráfego
│   └── iface/
│       └── iface.go     — lista interfaces, detecta gateway/IP local
└── ui/
    ├── index.html
    ├── style.css
    └── app.js
```

---

## Proposed Changes

### Backend Go

#### [NEW] `main.go`
- Inicializa o servidor HTTP na porta `9731`
- Abre janela WebView2 apontando para `http://localhost:9731`
- Tamanho 1200×750, título "NetPhantom"

#### [NEW] `internal/iface/iface.go`
- `ListInterfaces()` — lista todas NICs via `pcap.FindAllDevs()`
- `GetLocalInfo(iface)` — retorna IP local, MAC, gateway IP, gateway MAC

#### [NEW] `internal/arp/scanner.go`
- `ScanNetwork(iface, cidr)` — envia ARP requests para toda a faixa, coleta replies
- Retorna lista de `Host{IP, MAC, Hostname}`

#### [NEW] `internal/arp/spoof.go`
- `StartSpoof(iface, targetIP, gatewayIP, mode)` — loop goroutine que reenvia ARP replies falsos a cada 2s
- `StopSpoof()` — cancela goroutine via context
- Modo `"single"` — spoofeia apenas o target
- Modo `"network"` — spoofeia todos os hosts descobertos

#### [NEW] `internal/arp/dos.go`
- `StartDoS(iface, targetIP, gatewayIP)` — igual ao spoof mas **sem** IP forwarding → target perde conectividade
- `KillAll(iface, hosts)` — spoofeia toda rede ao mesmo tempo sem forwarding (botão "Derrubar Tudo")

#### [NEW] `internal/mitm/mitm.go`
- Habilita IP forwarding no Windows via registry (`HKLM\SYSTEM\...\IPEnableRouter`)
- Captura pacotes do target via BPF filter
- Extrai headers HTTP, DNS queries → stream de log

#### [NEW] `internal/server/server.go`
REST API:
| Método | Rota | Ação |
|--------|------|------|
| GET | `/api/interfaces` | lista NICs |
| POST | `/api/scan` | scan de rede |
| POST | `/api/spoof/start` | inicia ARP spoof |
| POST | `/api/spoof/stop` | para spoof |
| POST | `/api/dos/start` | inicia DoS |
| POST | `/api/dos/stop` | para DoS |
| POST | `/api/killall` | derruba toda rede |
| GET | `/api/logs/stream` | SSE — stream de logs em tempo real |
| GET | `/` | serve o frontend |

---

### Frontend UI

#### [NEW] `ui/index.html` + `ui/style.css` + `ui/app.js`

Interface com tema **dark cyber** (verde neon / fundo #0a0a0f):

**Abas:**
1. **Dashboard** — seletor de interface, botão Scan, tabela de hosts descobertos
2. **ARP Spoof** — alvo (IP ou "toda rede"), modo (MitM / DoS), botões Start/Stop
3. **Tráfego** — tabela live de pacotes capturados (HTTP, DNS, ARP)
4. **Logs** — terminal scrollável com SSE feed em tempo real

**Elementos fixos:**
- Header com status (●IDLE / ●SPOOFING / ●MitM / ●DoS)
- Botão vermelho "💀 DERRUBAR TUDO" no header — ação imediata em toda rede
- Badge de contador de pacotes capturados

---

## Verificação

1. `go build ./...` — compila sem erros
2. Executar como Administrator
3. Scan detecta hosts na rede local
4. Spoof altera cache ARP do alvo (verificável com `arp -a` no alvo)
5. Modo DoS — alvo perde conectividade
6. "Derrubar Tudo" — todos hosts da rede perdem conexão simultaneamente
7. Logs aparecem em tempo real na aba Logs e Tráfego

---

## Open Questions

> [!IMPORTANT]
> Confirme antes de eu soltar o build:
> 1. **Npcap já instalado?** (se não, o build compilará mas não vai funcionar sem ele)
> 2. **MinGW já configurado no PATH?** (necessário para CGO do gopacket)
> 3. **Captura de tráfego na aba "Tráfego"** — quer pacotes **decodificados** (HTTP body, DNS queries) ou apenas headers (src/dst IP/porta)?
