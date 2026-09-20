# Arpanet Suite

<div align="center">

![Arpanet Suite Logo](arpanet-suite-vector-assets/arpanet-suite-logo-primary.svg)

**Autonomous Layer-2 Network Security Auditing & Diagnostics Suite**  
*Available for Windows 10/11 (64-bit) & Android Mobile (APK)*

[![GitHub Release](https://img.shields.io/github/v/release/mk3bomfim/arpanet-suite?color=000000&style=for-the-badge&logo=github)](https://github.com/mk3bomfim/arpanet-suite/releases/tag/v2.0.0)
[![CI Build Status](https://img.shields.io/github/actions/workflow/status/mk3bomfim/arpanet-suite/build-apk.yml?branch=main&color=000000&style=for-the-badge&logo=githubactions)](https://github.com/mk3bomfim/arpanet-suite/actions)
[![Platform Windows](https://img.shields.io/badge/Platform-Windows%20x64-000000?style=for-the-badge&logo=windows)](https://github.com/mk3bomfim/arpanet-suite/releases/download/v2.0.0/arpanet.exe)
[![Platform Android](https://img.shields.io/badge/Platform-Android%20APK-000000?style=for-the-badge&logo=android)](https://github.com/mk3bomfim/arpanet-suite/releases/download/v2.0.0/arpanet.apk)

[🇧🇷 Português](#-português) • [🇺🇸 English](#-english)

---

### 📥 Downloads Oficiais / Official Downloads (v2.0.0)

| Plataforma / Platform | Arquivo / File | Tamanho / Size | Download Direto / Direct Link |
|---|---|---|---|
| **Windows 64-bit** | `arpanet.exe` | ~45 MB | [Download .EXE](https://github.com/mk3bomfim/arpanet-suite/releases/download/v2.0.0/arpanet.exe) |
| **Android Mobile** | `arpanet.apk` | 4.14 MB | [Download .APK](https://github.com/mk3bomfim/arpanet-suite/releases/download/v2.0.0/arpanet.apk) |

</div>

---

## 🇧🇷 Português

### Visão Geral
O **Arpanet Suite** é uma plataforma de alta performance desenvolvida para auditoria, inspeção e testes de estresse em redes locais (Layer-2). Integrando um backend em **Go** com motor de pacotes brutos via **Npcap** e uma interface de usuário minimalista monocromática, a suíte entrega velocidade extrema, controle preciso de pacotes ARP e telemetria ao vivo via Server-Sent Events (SSE).

### Funcionalidades
- **Varredura de Rede (ARP Sweep)**: Descoberta instantânea de dispositivos ativos no segmento `/24` ou personalizado com resolução de fabricante/hostname.
- **ARP Spoofing Bidirecional**: Envenenamento de cache ARP direcionado para análise e intercepção controlada de tráfego.
- **Isolamento de Alvo (DoS Controlado)**: Interrupção seletiva de tráfego de nós específicos sem IP forwarding.
- **Derrubar Tudo (Kill All)**: Spoofing massivo simultâneo em broadcast para contenção e testes de resiliência.
- **Logs e Telemetria em Tempo Real**: Transmissão contínua de eventos via Server-Sent Events (SSE).
- **Interface Monocromática**: Design puramente preto e branco (#000000 / #ffffff), sem emojis, com animações e adaptação nativa para telas sensíveis ao toque (Mobile M3).

### Requisitos do Sistema

#### Windows
1. **Npcap**: Necessário para injeção e captura de pacotes raw. Instale com a opção *"WinPcap API-compatible Mode"* marcada: [nmap.org/npcap](https://nmap.org/npcap/).
2. **Permissões**: Execute o `arpanet.exe` como **Administrador** para permitir acesso às placas de rede promiscuous.

#### Android
- Android 10+ (API 29 até API 35).
- Instalação via arquivo `.apk` ou diretamente como WebAPK/PWA pelo navegador apontando para a máquina de auditoria.

### Estrutura do Projeto
```
arpanet-suite/
├── main.go                     # Ponto de entrada Go (servidor HTTP + WebView2)
├── internal/
│   ├── arp/                    # Motor ARP (Scanner, Spoofing, DoS)
│   ├── iface/                  # Enumeração de NICs e detecção de gateway
│   ├── mitm/                   # Roteamento de pacotes e inspeção
│   └── server/                 # API REST e stream SSE
├── ui/                         # Interface frontend pura (HTML, Vanilla CSS, JS)
│   ├── index.html              # Console de comando monocromático
│   ├── landing.html            # Landing page com download animado
│   └── manifest.json           # Manifesto PWA
├── android/                    # Projeto nativo Android Capacitor 7
└── .github/workflows/          # Pipeline de build automatizado na nuvem
```

### Compilação Local (Opcional)

#### Compilar Executável Windows
```powershell
go build -o arpanet.exe -ldflags="-H windowsgui" .
```

#### Compilar APK Android
A compilação do APK roda automaticamente no GitHub Actions a cada push na branch `main`. Se desejar compilar localmente:
```powershell
cd android
npm install
npx cap sync android
cd android
./gradlew assembleDebug
```

---

## 🇺🇸 English

### Overview
**Arpanet Suite** is a high-performance framework engineered for Layer-2 network auditing, security inspection, and stress testing. Combining a raw socket **Go** backend powered by **Npcap** with a pure monochrome Material You web interface, it provides line-rate packet injection, precise ARP cache manipulation, and real-time telemetry streaming via Server-Sent Events (SSE).

### Key Features
- **ARP Network Sweep**: Instant host discovery across `/24` or custom subnets with IP, MAC, and vendor mapping.
- **Bidirectional ARP Spoofing**: Targeted cache poisoning for controlled man-in-the-middle diagnostic inspection.
- **Controlled Denial of Service (DoS)**: Drop forwarding to isolate specific offending network endpoints.
- **Network-Wide Kill Switch**: Simultaneous subnet-wide broadcast spoofing for incident containment testing.
- **Real-Time Telemetry**: Sub-millisecond event streaming via HTTP Server-Sent Events (SSE).
- **Pure Monochrome Interface**: Black & white design (#000000 / #ffffff), zero emojis, fluid micro-animations, and full mobile touch ergonomics (M3 Bottom Navigation).

### Requirements

#### Windows
1. **Npcap**: Required for raw packet transmission and promiscuous sniffing. Ensure *"WinPcap API-compatible Mode"* is checked during installation: [nmap.org/npcap](https://nmap.org/npcap/).
2. **Privileges**: Launch `arpanet.exe` as **Administrator** to grant socket manipulation permissions.

#### Android
- Android 10+ (API 29 through API 35).
- Install directly via `arpanet.apk` or add to home screen as WebAPK/PWA.

### Build from Source

#### Windows Executable
```powershell
go build -o arpanet.exe -ldflags="-H windowsgui" .
```

#### Android APK
The APK is continuously compiled and published via GitHub Actions on every push. For local builds:
```powershell
cd android
npm install
npx cap sync android
cd android
./gradlew assembleDebug
```

---

<div align="center">
<sub>ARPANET SUITE &bull; AUTHORIZED NETWORK AUDITING SUITE &bull; RELEASE V2.0.0</sub>
</div>
