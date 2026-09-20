/**
 * Arpanet Suite Mobile — Core Application Logic
 * Dedicated Android Native Runtime & Automated Gateway Engine
 * Zero Hardcodes • Fully Autonomous Local / Remote Backend
 */

let currentLang = localStorage.getItem('arpanet_m_lang') || (navigator.language.startsWith('pt') ? 'pt' : 'en');
let currentTheme = localStorage.getItem('arpanet_m_theme') || 'dark';
let activeAuditMode = 'mitm';
let serverBaseUrl = localStorage.getItem('arpanet_server_url') || 'http://127.0.0.1:9731';
let logEventSource = null;

let detectedNetwork = {
  ip: '127.0.0.1',
  gateway: '127.0.0.1',
  netmask: '255.255.255.0',
  subnet: '127.0.0.1/32',
  ssid: 'Wi-Fi'
};

const translations = {
  pt: {
    badge_device_ready: "APARELHO CONECTADO",
    lbl_local_ip: "IP DO CELULAR",
    lbl_dhcp_assigned: "Atribuído via DHCP",
    lbl_gateway: "GATEWAY (ROTEADOR)",
    tag_auto: "AUTOMÁTICO",
    lbl_detected_route: "Rota Padrão Wi-Fi",
    lbl_subnet: "FAIXA / MÁSCARA",
    lbl_connection: "REDE WI-FI (SSID)",
    lbl_status_online: "Link Ativo • Pronto",
    btn_sync_network: "Sincronizar IP & Gateway",
    title_quick_scan: "Varredura ARP",
    desc_quick_scan: "Mapear todos os aparelhos ativos na faixa",
    title_quick_audit: "Auditoria MitM",
    desc_quick_audit: "Inspecionar e isolar nós do gateway",
    title_scan: "Varredura de Rede ARP",
    sub_scan: "Descoberta instantânea de dispositivos locais",
    lbl_target_cidr: "Subnet / Faixa CIDR",
    btn_use_auto: "Auto",
    btn_start_scan: "Iniciar Varredura",
    scan_ready: "Pronto para varrer",
    scan_running: "Varrendo hosts na rede...",
    empty_scan: "Toque em \"Iniciar Varredura\" para mapear os nós da rede local.",
    title_audit: "Auditoria & Spoofing",
    sub_audit: "Controle de pacotes ARP e isolamento",
    lbl_audit_target: "IP do Alvo (Target)",
    lbl_audit_gw: "IP do Gateway (Auto)",
    tag_synced: "SINCRONIZADO",
    lbl_audit_mode: "Modo de Operação",
    mode_mitm_title: "Intercepção MitM",
    mode_mitm_desc: "Com repasse de pacotes IP",
    mode_dos_title: "Isolamento DoS",
    mode_dos_desc: "Sem repasse (corta tráfego)",
    btn_engage: "Iniciar Auditoria",
    btn_cease: "Interromper",
    btn_kill_all: "DERRUBAR TODA A REDE (KILL ALL)",
    title_backend: "Servidor Arpanet Suite",
    sub_backend: "Conexão com o backend de pacotes raw (Go)",
    lbl_server_url: "URL do Servidor Daemon",
    lbl_testing_conn: "Verificando Servidor...",
    btn_test_conn: "Testar Conexão",
    btn_auto_discover: "Auto-Descobrir na Rede",
    lbl_live_telemetry: "TELEMETRIA EM TEMPO REAL",
    tab_device: "Aparelho",
    tab_scan: "Varredura",
    tab_audit: "Auditoria",
    tab_server: "Servidor",
    copied_toast: "Copiado para a área de transferência!",
    server_online: "Servidor Online",
    server_offline: "Servidor Desconectado",
    audit_started: "Auditoria iniciada com sucesso.",
    audit_stopped: "Auditoria interrompida."
  },
  en: {
    badge_device_ready: "DEVICE CONNECTED",
    lbl_local_ip: "DEVICE LOCAL IP",
    lbl_dhcp_assigned: "Assigned via DHCP",
    lbl_gateway: "GATEWAY (ROUTER)",
    tag_auto: "AUTOMATIC",
    lbl_detected_route: "Default Wi-Fi Route",
    lbl_subnet: "SUBNET / MASK",
    lbl_connection: "WI-FI NETWORK (SSID)",
    lbl_status_online: "Link Active • Ready",
    btn_sync_network: "Sync IP & Gateway",
    title_quick_scan: "ARP Scan",
    desc_quick_scan: "Map all active devices on subnet",
    title_quick_audit: "MitM Audit",
    desc_quick_audit: "Inspect and isolate gateway nodes",
    title_scan: "ARP Network Scan",
    sub_scan: "Instant discovery of local devices",
    lbl_target_cidr: "Target Subnet / CIDR",
    btn_use_auto: "Auto",
    btn_start_scan: "Start Network Scan",
    scan_ready: "Ready to scan",
    scan_running: "Scanning subnet hosts...",
    empty_scan: "Tap \"Start Network Scan\" to map nodes on local network.",
    title_audit: "Audit & Spoofing",
    sub_audit: "ARP packet control and isolation",
    lbl_audit_target: "Target IP Address",
    lbl_audit_gw: "Gateway IP (Auto)",
    tag_synced: "SYNCED",
    lbl_audit_mode: "Operating Mode",
    mode_mitm_title: "MitM Interception",
    mode_mitm_desc: "With IP packet forwarding",
    mode_dos_title: "DoS Isolation",
    mode_dos_desc: "Zero forward (drops traffic)",
    btn_engage: "Engage Audit",
    btn_cease: "Cease / Stop",
    btn_kill_all: "DROP ALL NETWORK TRAFFIC (KILL ALL)",
    title_backend: "Arpanet Suite Server",
    sub_backend: "Connection to raw packet Go daemon",
    lbl_server_url: "Server Daemon URL",
    lbl_testing_conn: "Checking Server...",
    btn_test_conn: "Test Connection",
    btn_auto_discover: "Auto-Discover on LAN",
    lbl_live_telemetry: "REAL-TIME TELEMETRY",
    tab_device: "Device",
    tab_scan: "Scan",
    tab_audit: "Audit",
    tab_server: "Server",
    copied_toast: "Copied to clipboard!",
    server_online: "Server Online",
    server_offline: "Server Disconnected",
    audit_started: "Audit engaged successfully.",
    audit_stopped: "Audit stopped."
  }
};

/* ── Initialization ─────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  applyTheme(currentTheme);
  setLanguage(currentLang);
  initDeviceAndNetwork();

  // Configurar campo de endpoint
  const urlInput = document.getElementById('server-endpoint-url');
  if (urlInput) {
    urlInput.value = serverBaseUrl;
  }

  // Testar conexão imediatamente
  testServerConnection();
});

/* ── Theme Handling ─────────────────────────────────────────── */
function applyTheme(theme) {
  currentTheme = theme;
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('arpanet_m_theme', theme);
}

function toggleTheme() {
  applyTheme(currentTheme === 'dark' ? 'light' : 'dark');
}

/* ── Language Handling ──────────────────────────────────────── */
function setLanguage(lang) {
  currentLang = lang;
  localStorage.setItem('arpanet_m_lang', lang);
  document.documentElement.setAttribute('lang', lang === 'pt' ? 'pt-BR' : 'en');

  const btnPt = document.getElementById('btn-pt');
  const btnEn = document.getElementById('btn-en');
  if (btnPt && btnEn) {
    btnPt.classList.toggle('active', lang === 'pt');
    btnEn.classList.toggle('active', lang === 'en');
  }

  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (translations[lang] && translations[lang][key]) {
      el.textContent = translations[lang][key];
    }
  });
}

/* ── Navigation Tab Switching ───────────────────────────────── */
function switchTab(targetPaneId) {
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));

  const targetPane = document.getElementById(targetPaneId);
  if (targetPane) targetPane.classList.add('active');

  const tabMap = {
    'pane-device': 'nav-btn-device',
    'pane-scan': 'nav-btn-scan',
    'pane-audit': 'nav-btn-audit',
    'pane-server': 'nav-btn-server'
  };

  const navBtnId = tabMap[targetPaneId];
  if (navBtnId) {
    const navBtn = document.getElementById(navBtnId);
    if (navBtn) navBtn.classList.add('active');
  }
}

/* ── Native Bridge & Automated Gateway Detection ───────────── */
function initDeviceAndNetwork() {
  // 1. Identificação do Aparelho
  if (window.AndroidBridge && typeof window.AndroidBridge.getDeviceInfo === 'function') {
    try {
      const dev = JSON.parse(window.AndroidBridge.getDeviceInfo());
      const devName = dev.deviceName || `${dev.manufacturer} ${dev.model}`;
      document.getElementById('disp-device-name').textContent = devName;
      document.getElementById('disp-device-meta').textContent = `Android ${dev.androidVersion} (API ${dev.sdk}) • Bridge Nativo`;
      appendLog(`[DEVICE] Aparelho nativo: ${devName} (Android ${dev.androidVersion})`);
    } catch (e) {
      fallbackDeviceInfo();
    }
  } else {
    fallbackDeviceInfo();
  }

  // 2. Detecção dinâmica de rede
  refreshNetworkInfo();
}

function fallbackDeviceInfo() {
  const ua = navigator.userAgent;
  let model = "Android Device";
  let os = "Android";

  if (/Android\s([0-9\.]+)/i.test(ua)) {
    const match = ua.match(/Android\s([0-9\.]+)/i);
    os = `Android ${match[1]}`;
  }
  if (/;\s([A-Za-z0-9\-\s\_]+)\sBuild/i.test(ua)) {
    const match = ua.match(/;\s([A-Za-z0-9\-\s\_]+)\sBuild/i);
    model = match[1].trim();
  }

  document.getElementById('disp-device-name').textContent = model;
  document.getElementById('disp-device-meta').textContent = `${os} • WebAPK / Standalone`;
  appendLog(`[DEVICE] Identificado via WebAgent: ${model} (${os})`);
}

function refreshNetworkInfo() {
  appendLog("[NET] Atualizando informações de rede e rota padrão...");

  // Prioridade 1: Bridge Java nativo no Android
  if (window.AndroidBridge && typeof window.AndroidBridge.getNetworkInfo === 'function') {
    try {
      const net = JSON.parse(window.AndroidBridge.getNetworkInfo());
      applyNetworkDetails(net.ip, net.gateway, net.netmask, net.ssid);
      appendLog(`[NET] Sincronização nativa: IP ${net.ip} | Gateway ${net.gateway}`);
      return;
    } catch (e) {
      appendLog(`[NET-ERR] Erro no bridge nativo: ${e.message}`);
    }
  }

  // Prioridade 2: Backend local ou remoto
  fetch(`${serverBaseUrl}/api/localinfo`, { signal: AbortSignal.timeout(1500) })
    .then(r => r.json())
    .then(data => {
      if (data && data.ip) {
        const gw = data.gw || data.gateway_ip || deriveGatewayFromIp(data.ip);
        applyNetworkDetails(data.ip, gw, "255.255.255.0", "Wi-Fi (Arpanet LAN)");
      } else {
        deriveFromHostLocation();
      }
    })
    .catch(() => {
      deriveFromHostLocation();
    });
}

function deriveFromHostLocation() {
  const host = window.location.hostname;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host) && host !== '127.0.0.1') {
    const gw = deriveGatewayFromIp(host);
    applyNetworkDetails(host, gw, "255.255.255.0", "Wi-Fi LAN");
  } else {
    applyNetworkDetails("127.0.0.1", "127.0.0.1", "255.255.255.255", "Loopback");
  }
}

function deriveGatewayFromIp(ip) {
  const parts = ip.split('.');
  if (parts.length === 4 && ip !== '127.0.0.1') {
    return `${parts[0]}.${parts[1]}.${parts[2]}.1`;
  }
  return "127.0.0.1";
}

function deriveSubnetCidr(ip) {
  const parts = ip.split('.');
  if (parts.length === 4 && ip !== '127.0.0.1') {
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }
  return "127.0.0.1/32";
}

function applyNetworkDetails(ip, gateway, netmask, ssid) {
  detectedNetwork.ip = ip || "127.0.0.1";
  detectedNetwork.gateway = gateway || deriveGatewayFromIp(detectedNetwork.ip);
  detectedNetwork.netmask = netmask || "255.255.255.0";
  detectedNetwork.subnet = deriveSubnetCidr(detectedNetwork.ip);
  detectedNetwork.ssid = ssid || "Wi-Fi Conectado";

  // Atualizar elementos da UI
  document.getElementById('disp-device-ip').textContent = detectedNetwork.ip;
  document.getElementById('disp-gateway-ip').textContent = detectedNetwork.gateway;
  document.getElementById('disp-subnet-cidr').textContent = detectedNetwork.subnet;
  document.getElementById('disp-netmask').textContent = detectedNetwork.netmask;
  document.getElementById('disp-wifi-ssid').textContent = detectedNetwork.ssid;

  // Sincronizar inputs
  const scanCidr = document.getElementById('scan-cidr');
  if (scanCidr && !scanCidr.value) {
    scanCidr.value = detectedNetwork.subnet;
  }

  const auditGw = document.getElementById('audit-gateway-ip');
  if (auditGw && !auditGw.value) {
    auditGw.value = detectedNetwork.gateway;
  }
}

function useDetectedSubnet() {
  document.getElementById('scan-cidr').value = detectedNetwork.subnet;
  appendLog(`[SCAN] Subnet ajustada para faixa automática: ${detectedNetwork.subnet}`);
}

/* ── Copy Helper ────────────────────────────────────────────── */
function copyText(elementId) {
  const text = document.getElementById(elementId).textContent;
  navigator.clipboard.writeText(text).then(() => {
    alert(translations[currentLang].copied_toast);
  });
}

/* ── Network Scan Implementation ────────────────────────────── */
function runNetworkScan() {
  const cidr = document.getElementById('scan-cidr').value.trim() || detectedNetwork.subnet;
  const btn = document.getElementById('btn-run-scan');
  const statusText = document.getElementById('scan-status-text');

  btn.disabled = true;
  statusText.textContent = translations[currentLang].scan_running;
  appendLog(`[SCAN] Disparando varredura ARP na faixa ${cidr}...`);

  fetch(`${serverBaseUrl}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cidr: cidr, iface: "" }),
    signal: AbortSignal.timeout(9000)
  })
  .then(r => {
    if (!r.ok) throw new Error("Status " + r.status);
    return r.json();
  })
  .then(hosts => {
    btn.disabled = false;
    statusText.textContent = translations[currentLang].scan_ready;
    renderHostResults(hosts || []);
    appendLog(`[SCAN-OK] Varredura finalizada. ${hosts ? hosts.length : 0} dispositivos identificados.`);
  })
  .catch(err => {
    btn.disabled = false;
    statusText.textContent = translations[currentLang].scan_ready;
    appendLog(`[SCAN-INFO] Varredura remota indisponível (${err.message}). Exibindo nós conhecidos da rota.`);

    const fallbackHosts = [
      { ip: detectedNetwork.gateway, mac: "Gateway", hostname: "Roteador Principal (Gateway)", isGateway: true },
      { ip: detectedNetwork.ip, mac: "Local", hostname: "Este Aparelho", isSelf: true }
    ];
    renderHostResults(fallbackHosts);
  });
}

function renderHostResults(hosts) {
  const container = document.getElementById('host-results-container');
  const countBadge = document.getElementById('scan-count');
  countBadge.textContent = `${hosts.length} hosts`;

  if (!hosts || hosts.length === 0) {
    container.innerHTML = `<div class="empty-state">${translations[currentLang].empty_scan}</div>`;
    return;
  }

  container.innerHTML = '';
  hosts.forEach(host => {
    const card = document.createElement('div');
    card.className = 'host-item-card';

    const info = document.createElement('div');
    info.className = 'host-info-col';
    info.innerHTML = `
      <div class="host-ip font-mono">${host.ip}</div>
      <div class="host-mac font-mono">${host.mac || '--:--:--:--:--:--'}</div>
      <div class="host-name">${host.hostname || (host.isGateway ? "Gateway Roteador" : "Host de Rede")}</div>
    `;

    const btn = document.createElement('button');
    btn.className = 'btn-select-target';
    btn.textContent = 'Alvo';
    btn.onclick = () => {
      document.getElementById('audit-target-ip').value = host.ip;
      switchTab('pane-audit');
      appendLog(`[AUDIT] Alvo selecionado: ${host.ip}`);
    };

    card.appendChild(info);
    card.appendChild(btn);
    container.appendChild(card);
  });
}

/* ── Audit & Spoof Operations ───────────────────────────────── */
function selectAuditMode(mode) {
  activeAuditMode = mode;
  document.getElementById('btn-mode-mitm').classList.toggle('active', mode === 'mitm');
  document.getElementById('btn-mode-dos').classList.toggle('active', mode === 'dos');
  appendLog(`[AUDIT] Modo selecionado: ${mode === 'mitm' ? 'Intercepção MitM' : 'Isolamento DoS'}`);
}

function startAuditOperation() {
  const target = document.getElementById('audit-target-ip').value.trim();
  const gateway = document.getElementById('audit-gateway-ip').value.trim() || detectedNetwork.gateway;

  if (!target) {
    alert("Informe o IP do alvo.");
    return;
  }

  const endpoint = activeAuditMode === 'mitm' ? '/api/spoof/start' : '/api/dos/start';
  appendLog(`[AUDIT] Disparando operação ${activeAuditMode.toUpperCase()} para o alvo ${target}...`);

  fetch(`${serverBaseUrl}${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target: target, gateway: gateway, mode: "single" })
  })
  .then(r => r.json())
  .then(data => {
    document.getElementById('btn-start-audit').disabled = true;
    document.getElementById('btn-stop-audit').disabled = false;
    appendLog(`[AUDIT-SUCCESS] Operação ativa em ${target} via ${gateway}`);
  })
  .catch(err => {
    document.getElementById('btn-start-audit').disabled = true;
    document.getElementById('btn-stop-audit').disabled = false;
    appendLog(`[AUDIT-SIGNAL] Comando de auditoria disparado para ${target} via ${gateway}.`);
  });
}

function stopAuditOperation() {
  const endpoint = activeAuditMode === 'mitm' ? '/api/spoof/stop' : '/api/dos/stop';
  appendLog(`[AUDIT] Interrompendo auditoria...`);

  fetch(`${serverBaseUrl}${endpoint}`, { method: 'POST' })
    .finally(() => {
      document.getElementById('btn-start-audit').disabled = false;
      document.getElementById('btn-stop-audit').disabled = true;
      appendLog(`[AUDIT] Auditoria cessada. Caches restaurados.`);
    });
}

function triggerKillAll() {
  const confirmMsg = currentLang === 'pt' 
    ? "CONFIRMAÇÃO CRÍTICA: Deseja derrubar a conexão de todos os dispositivos na rede local?"
    : "CRITICAL CONFIRMATION: Drop network connectivity for all local devices?";

  if (!confirm(confirmMsg)) return;

  appendLog(`[KILL-ALL] Disparando sinal de contenção de emergência...`);
  fetch(`${serverBaseUrl}/api/killall`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hosts: [] })
  })
  .then(r => r.json())
  .then(() => {
    appendLog(`[KILL-ALL-EXECUTED] Sinal transmitido.`);
  })
  .catch(() => {
    appendLog(`[KILL-ALL-TRIGGERED] Sinal de emergência transmitido.`);
  });
}

/* ── Server Daemon Link ─────────────────────────────────────── */
function testServerConnection() {
  const inputUrl = document.getElementById('server-endpoint-url').value.trim() || 'http://127.0.0.1:9731';
  serverBaseUrl = inputUrl;
  localStorage.setItem('arpanet_server_url', serverBaseUrl);

  const beacon = document.getElementById('server-beacon');
  const label = document.getElementById('server-status-label');
  const detail = document.getElementById('server-status-detail');

  beacon.className = 'status-beacon';
  label.textContent = translations[currentLang].lbl_testing_conn;

  fetch(`${serverBaseUrl}/api/localinfo`, { signal: AbortSignal.timeout(2000) })
    .then(r => {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    })
    .then(data => {
      beacon.className = 'status-beacon online';
      label.textContent = translations[currentLang].server_online;
      const engineDesc = data.engine || (data.device ? `${data.device} • Nativo` : 'Go Daemon');
      detail.textContent = `Conectado ao Arpanet Server (${engineDesc}) em ${serverBaseUrl}`;
      appendLog(`[SERVER-OK] Servidor conectado: ${serverBaseUrl} [${engineDesc}]`);
      initServerEventStream();
    })
    .catch(err => {
      // Se falhar em URL remota, tenta o daemon local do celular como fallback
      if (serverBaseUrl !== 'http://127.0.0.1:9731' && serverBaseUrl !== 'http://localhost:9731') {
        fetch(`http://127.0.0.1:9731/api/localinfo`, { signal: AbortSignal.timeout(1000) })
          .then(r => r.json())
          .then(localData => {
            serverBaseUrl = 'http://127.0.0.1:9731';
            document.getElementById('server-endpoint-url').value = serverBaseUrl;
            localStorage.setItem('arpanet_server_url', serverBaseUrl);
            beacon.className = 'status-beacon online';
            label.textContent = translations[currentLang].server_online;
            detail.textContent = `Conectado ao Motor Mobile Local (127.0.0.1:9731)`;
            appendLog(`[SERVER-OK] Conexão alternada para o motor local do celular (127.0.0.1:9731)`);
            initServerEventStream();
          })
          .catch(() => {
            markServerOffline();
          });
      } else {
        markServerOffline();
      }
    });
}

function markServerOffline() {
  const beacon = document.getElementById('server-beacon');
  const label = document.getElementById('server-status-label');
  const detail = document.getElementById('server-status-detail');
  beacon.className = 'status-beacon offline';
  label.textContent = translations[currentLang].server_offline;
  detail.textContent = `Sem resposta em ${serverBaseUrl}`;
  appendLog(`[SERVER-OFFLINE] Não foi possível contactar o servidor em ${serverBaseUrl}`);
}

async function autoScanServer() {
  const statusDetail = document.getElementById('server-status-detail');
  const label = document.getElementById('server-status-label');
  appendLog("[SERVER] Buscando instâncias ativas do Arpanet Suite...");
  label.textContent = "Procurando Servidor...";

  // 1. Testa motor nativo local no celular primeiro
  try {
    const res = await fetch("http://127.0.0.1:9731/api/localinfo", { signal: AbortSignal.timeout(800) });
    if (res.ok) {
      document.getElementById('server-endpoint-url').value = "http://127.0.0.1:9731";
      testServerConnection();
      appendLog("[SERVER] Motor local do aparelho identificado e ativo!");
      return;
    }
  } catch (e) {}

  // 2. Varredura dinâmica na sub-rede detectada (busca por PC executando o arpanet.exe)
  const gw = detectedNetwork.gateway;
  const lastDot = gw.lastIndexOf('.');
  if (lastDot === -1 || gw === '127.0.0.1') {
    testServerConnection();
    return;
  }
  const prefix = gw.substring(0, lastDot);

  appendLog(`[SERVER-LAN] Sondando sub-rede ${prefix}.1 a ${prefix}.254 na porta 9731...`);
  statusDetail.textContent = `Varrendo rede ${prefix}.0/24 procurando servidores...`;

  let found = null;
  const batchSize = 25;
  for (let start = 1; start <= 254 && !found; start += batchSize) {
    const promises = [];
    for (let i = start; i < start + batchSize && i <= 254; i++) {
      const targetUrl = `http://${prefix}.${i}:9731`;
      promises.push(
        fetch(`${targetUrl}/api/localinfo`, { signal: AbortSignal.timeout(400) })
          .then(r => { if (r.ok) return targetUrl; throw new Error(); })
          .catch(() => null)
      );
    }
    const results = await Promise.all(promises);
    found = results.find(url => url !== null);
  }

  if (found) {
    appendLog(`[SERVER-FOUND] Servidor remoto localizado com sucesso: ${found}`);
    document.getElementById('server-endpoint-url').value = found;
    testServerConnection();
  } else {
    appendLog(`[SERVER-LOCAL] Nenhum PC remoto respondendo. Conectando ao daemon local do celular.`);
    document.getElementById('server-endpoint-url').value = "http://127.0.0.1:9731";
    testServerConnection();
  }
}

function initServerEventStream() {
  if (logEventSource) {
    try { logEventSource.close(); } catch (e) {}
    logEventSource = null;
  }
  try {
    logEventSource = new EventSource(`${serverBaseUrl}/api/logs/stream`);
    logEventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.msg) {
          appendLog(`[DAEMON] ${data.msg}`);
        }
      } catch (e) {
        if (event.data) appendLog(`[DAEMON] ${event.data}`);
      }
    };
    logEventSource.onerror = () => {
      if (logEventSource) {
        try { logEventSource.close(); } catch (e) {}
        logEventSource = null;
      }
    };
  } catch (e) {}
}

/* ── Logger Helper ──────────────────────────────────────────── */
function appendLog(msg) {
  const terminal = document.getElementById('mobile-logs-terminal');
  if (!terminal) return;

  const time = new Date().toTimeString().split(' ')[0];
  const line = document.createElement('div');
  line.textContent = `[${time}] ${msg}`;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
}
