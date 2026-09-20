# Arpanet Suite

<div align="center">

![Arpanet Suite Logo](arpanet-suite-vector-assets/arpanet-suite-logo-primary.svg)

**Autonomous Layer-2 Network Security Auditing & Diagnostics Suite**  
*Available for Windows 10/11 (64-bit) & Android Mobile (APK)*

[![Landing Page](https://img.shields.io/badge/🌐%20Site%20Oficial-net--nu--one.vercel.app-000000?style=for-the-badge)](https://net-nu-one.vercel.app/landing)
[![GitHub Release](https://img.shields.io/github/v/release/mk3bomfim/arpanet-suite?color=000000&style=for-the-badge&logo=github)](https://github.com/mk3bomfim/arpanet-suite/releases/latest)
[![CI Build Status](https://img.shields.io/github/actions/workflow/status/mk3bomfim/arpanet-suite/build-apk.yml?branch=main&color=000000&style=for-the-badge&logo=githubactions)](https://github.com/mk3bomfim/arpanet-suite/actions)
[![Platform Windows](https://img.shields.io/badge/Platform-Windows%20x64-000000?style=for-the-badge&logo=windows)](https://github.com/mk3bomfim/arpanet-suite/releases/latest/download/arpanet.exe)
[![Platform Android](https://img.shields.io/badge/Platform-Android%20APK-000000?style=for-the-badge&logo=android)](https://github.com/mk3bomfim/arpanet-suite/releases/latest/download/arpanet-suite.apk)

### 🌐 [net-nu-one.vercel.app/landing](https://net-nu-one.vercel.app/landing)

[🇧🇷 Português](#-português) • [🇺🇸 English](#-english)

---

### 📥 Downloads Oficiais / Official Downloads

| Plataforma / Platform | Arquivo / File | Download Direto / Direct Link |
|---|---|---|
| **Windows 64-bit** | `arpanet.exe` | [Download .EXE](https://github.com/mk3bomfim/arpanet-suite/releases/latest/download/arpanet.exe) |
| **Android Mobile** | `arpanet-suite.apk` | [Download .APK](https://github.com/mk3bomfim/arpanet-suite/releases/latest/download/arpanet-suite.apk) |

</div>

---

## 🇧🇷 Português

### Visão Geral
O **Arpanet Suite** é uma plataforma de alta performance desenvolvida para auditoria, inspeção e testes de estresse em redes locais (Layer-2). Integrando um backend em **Go** com motor de pacotes brutos via **Npcap** e uma interface de usuário minimalista monocromática, a suíte entrega velocidade extrema, controle preciso de pacotes ARP e telemetria ao vivo via Server-Sent Events (SSE).

### Funcionalidades
- **Varredura de Rede (ARP Sweep)**: Descoberta instantânea de dispositivos ativos no segmento `/24` ou personalizado com resolução de fabricante/hostname.
- **ARP Spoofing Bidirecional**: Envenenamento de cache ARP direcionado para análise e intercepção controlada de tráfego.
- **Isolamento de Alvo (DoS Controlado)**: Interrupção seletiva de tráfego de nós específicos sem IP forwarding.
- **Painel Kill All com Timer**: Seleção granular de alvos por checkbox, duração configurável (chips + campo livre) e timer SVG animado com restauração automática da rede.
- **Gateway Automático**: Detecção dinâmica do IP e gateway sem nenhum valor fixo no código.
- **Logs e Telemetria em Tempo Real**: Transmissão contínua de eventos via Server-Sent Events (SSE).
- **Interface Monocromática**: Design puramente preto e branco (#000000 / #ffffff), sem emojis, com animações e adaptação nativa para telas sensíveis ao toque (Mobile M3).

### Requisitos do Sistema

#### Windows
1. **Npcap**: Necessário para injeção e captura de pacotes raw. Instale com a opção *"WinPcap API-compatible Mode"* marcada: [nmap.org/npcap](https://nmap.org/npcap/).
2. **Permissões**: Execute o `arpanet.exe` como **Administrador** para permitir acesso às placas de rede promiscuous.

#### Android
- Android 10+ (API 29 até API 35).
- Instalação via arquivo `.apk` direto da aba [Releases](https://github.com/mk3bomfim/arpanet-suite/releases/latest).

### Estrutura do Projeto
```
arpanet-suite/
├── main.go                     # Ponto de entrada Go (servidor HTTP + WebView2)
├── arp.go                      # Motor ARP (Scanner, Spoofing, DoS)
├── mitm.go                     # Roteamento de pacotes e inspeção
├── server.go                   # API REST e stream SSE
├── ui/                         # Interface frontend pura (HTML, Vanilla CSS, JS)
│   ├── index.html              # Console de comando monocromático
│   ├── landing.html            # Landing page com download animado
│   └── manifest.json           # Manifesto PWA
├── android/                    # Projeto nativo Android Capacitor 7
│   └── ui/                     # UI mobile dedicada (Material You)
└── .github/workflows/          # Pipeline de build + release automatizado
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
- **Kill All Panel with Timer**: Per-device checkbox selection, configurable block duration (quick chips + custom input), animated SVG countdown ring, and automatic network restore.
- **Zero-Hardcode Gateway**: Dynamic OS-level IP and gateway detection — no fixed values in code.
- **Real-Time Telemetry**: Sub-millisecond event streaming via HTTP Server-Sent Events (SSE).
- **Pure Monochrome Interface**: Black & white design (#000000 / #ffffff), zero emojis, fluid micro-animations, and full mobile touch ergonomics (M3 Bottom Navigation).

### Requirements

#### Windows
1. **Npcap**: Required for raw packet transmission and promiscuous sniffing. Ensure *"WinPcap API-compatible Mode"* is checked during installation: [nmap.org/npcap](https://nmap.org/npcap/).
2. **Privileges**: Launch `arpanet.exe` as **Administrator** to grant socket manipulation permissions.

#### Android
- Android 10+ (API 29 through API 35).
- Install directly via `.apk` from the [Releases page](https://github.com/mk3bomfim/arpanet-suite/releases/latest).

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
<sub>ARPANET SUITE &bull; AUTHORIZED NETWORK AUDITING SUITE &bull; RELEASE V2 &bull; <a href="https://net-nu-one.vercel.app/landing">net-nu-one.vercel.app/landing</a></sub>
</div>
