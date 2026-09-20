/* ── Arpanet Suite — Core Logic & i18n Engine ─────────────────────── */

const API = 'http://localhost:9731/api';

// ─── i18n Dictionary ───────────────────────────────────────────────
const translations = {
  en: {
    appTitle: "Arpanet Suite",
    version: "v2.0",
    landingLink: "View Presentation Landing Page →",
    statusIdle: "IDLE",
    statusScanning: "SCANNING",
    statusSpoofing: "SPOOFING ACTIVE",
    statusKillAll: "NETWORK SUPPRESSION ACTIVE",
    interfaceLabel: "Network Interface",
    gatewayLabel: "Gateway IP",
    gatewayPlaceholder: "e.g. 192.168.1.1",
    detectGatewayTooltip: "Auto-detect Gateway",
    packetsLabel: "PKTS",
    sessionsLabel: "SESS",
    btnKillAll: "KILL NETWORK",
    btnKillStop: "STOP ATTACK",
    navDashboard: "Dashboard",
    navSpoof: "ARP Spoofing",
    navTraffic: "Traffic",
    navLogs: "Audit Logs",
    cidrLabel: "CIDR Range",
    btnScan: "Scan Subnet",
    scanningProgress: "Scanning targets...",
    tableIp: "IP Address",
    tableMac: "MAC Address",
    tableVendor: "Vendor / Hostname",
    tableActions: "Actions",
    noHostsFound: "No hosts detected. Click Scan Subnet to discover targets.",
    spoofConfigTitle: "Attack Parameters",
    targetIpLabel: "Target IP",
    targetMacLabel: "Target MAC (Auto/Manual)",
    attackModeLabel: "Attack Vector",
    modeMitm: "Man-in-the-Middle (Full Interception)",
    modeDos: "Denial-of-Service (Disable Connection)",
    rateLabel: "Interval (ms)",
    btnStartSpoof: "Launch Operation",
    btnStopSpoof: "Terminate Operation",
    filterProtocol: "Protocol Filter",
    filterAll: "All Protocols",
    btnClearTraffic: "Clear Table",
    btnExportCsv: "Export CSV",
    tableTime: "Timestamp",
    tableProto: "Proto",
    tableSource: "Source",
    tableDest: "Destination",
    tableLength: "Length",
    tableSummary: "Payload Summary",
    noTraffic: "Listening for packets...",
    btnClearLogs: "Clear Log History",
    killConfirmMsg: "Execute network-wide ARP disruption? All devices on subnet will lose connectivity.",
    hostsDiscovered: "hosts discovered"
  },
  pt: {
    appTitle: "Arpanet Suite",
    version: "v2.0",
    landingLink: "Acessar Landing Page de Apresentação →",
    statusIdle: "INATIVO",
    statusScanning: "ESCANEANDO",
    statusSpoofing: "SPOOFING ATIVO",
    statusKillAll: "DERRUBADA DE REDE ATIVA",
    interfaceLabel: "Interface de Rede",
    gatewayLabel: "IP do Gateway",
    gatewayPlaceholder: "ex: 192.168.1.1",
    detectGatewayTooltip: "Detectar Gateway",
    packetsLabel: "PKTS",
    sessionsLabel: "SESS",
    btnKillAll: "DERRUBAR TUDO",
    btnKillStop: "PARAR ATAQUE",
    navDashboard: "Painel",
    navSpoof: "ARP Spoofing",
    navTraffic: "Tráfego",
    navLogs: "Logs de Auditoria",
    cidrLabel: "Faixa CIDR",
    btnScan: "Escanear Rede",
    scanningProgress: "Escaneando alvos...",
    tableIp: "Endereço IP",
    tableMac: "Endereço MAC",
    tableVendor: "Fabricante / Hostname",
    tableActions: "Ações",
    noHostsFound: "Nenhum host detectado. Clique em Escanear Rede.",
    spoofConfigTitle: "Parâmetros de Operação",
    targetIpLabel: "IP do Alvo",
    targetMacLabel: "MAC do Alvo (Auto/Manual)",
    attackModeLabel: "Vetor de Ataque",
    modeMitm: "Man-in-the-Middle (Interceptação Total)",
    modeDos: "Negação de Serviço (Derrubar Conexão)",
    rateLabel: "Intervalo (ms)",
    btnStartSpoof: "Iniciar Operação",
    btnStopSpoof: "Encerrar Operação",
    filterProtocol: "Filtro de Protocolo",
    filterAll: "Todos os Protocolos",
    btnClearTraffic: "Limpar Tabela",
    btnExportCsv: "Exportar CSV",
    tableTime: "Horário",
    tableProto: "Proto",
    tableSource: "Origem",
    tableDest: "Destino",
    tableLength: "Tamanho",
    tableSummary: "Resumo do Pacote",
    noTraffic: "Aguardando captura de pacotes...",
    btnClearLogs: "Limpar Histórico",
    killConfirmMsg: "Executar ataque generalizado de ARP na rede? Todos os dispositivos conectados perderão o acesso.",
    hostsDiscovered: "hosts descobertos"
  }
};

let currentLang = localStorage.getItem('arpanet_lang') || 'pt';
let currentTheme = localStorage.getItem('arpanet_theme') || 'dark';

// ─── State Management ──────────────────────────────────────────────
let state = {
  currentTab: 'dashboard',
  selectedIface: '',
  gatewayIP: '',
  cidr: '',
  hosts: [],
  isScanning: false,
  isSpoofing: false,
  isKillAll: false,
  packetCount: 0,
  packets: [],
  maxPackets: 400,
  protocolFilter: 'ALL',
  logEventSource: null,
  packetEventSource: null
};

// ─── Initialization ────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initLanguage();
  setupTabs();
  loadInterfaces();
  initSSE();
});

// ─── Theme Toggler ─────────────────────────────────────────────────
function initTheme() {
  document.documentElement.setAttribute('data-theme', currentTheme);
  updateThemeIcon();
}

function toggleTheme() {
  currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', currentTheme);
  localStorage.setItem('arpanet_theme', currentTheme);
  updateThemeIcon();
}

function updateThemeIcon() {
  const icon = document.getElementById('theme-icon');
  if (!icon) return;
  if (currentTheme === 'dark') {
    // Sun icon for switching to light
    icon.innerHTML = `<path d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>`;
  } else {
    // Moon icon for switching to dark
    icon.innerHTML = `<path d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" stroke="currentColor" stroke-width="2" fill="none"/>`;
  }
}

// ─── Language Engine ───────────────────────────────────────────────
function initLanguage() {
  setLanguage(currentLang);
}

function setLanguage(lang) {
  currentLang = lang;
  localStorage.setItem('arpanet_lang', lang);
  
  // Update segmented buttons
  const btnEn = document.getElementById('lang-en');
  const btnPt = document.getElementById('lang-pt');
  if (btnEn && btnPt) {
    btnEn.classList.toggle('active', lang === 'en');
    btnPt.classList.toggle('active', lang === 'pt');
  }

  // Update all DOM elements with data-i18n
  const dict = translations[lang];
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (dict[key]) {
      if (el.tagName === 'INPUT' && el.hasAttribute('placeholder')) {
        el.placeholder = dict[key];
      } else if (el.hasAttribute('title') && el.querySelector('svg')) {
        el.setAttribute('title', dict[key]);
      } else {
        el.textContent = dict[key];
      }
    }
  });

  // Update elements with data-i18n-title
  document.querySelectorAll('[data-i18n-title]').forEach(el => {
    const key = el.getAttribute('data-i18n-title');
    if (dict[key]) {
      el.setAttribute('title', dict[key]);
      el.setAttribute('aria-label', dict[key]);
    }
  });

  updateStatusDisplay();
}

// ─── Navigation (Desktop & Android Mobile) ─────────────────────────
function setupTabs() {
  const desktopTabs = document.querySelectorAll('.nav-tab');
  const bottomTabs = document.querySelectorAll('.bottom-tab');

  function switchTab(tabId) {
    state.currentTab = tabId;

    desktopTabs.forEach(t => {
      t.classList.toggle('active', t.getAttribute('data-tab') === tabId);
    });

    bottomTabs.forEach(t => {
      t.classList.toggle('active', t.getAttribute('data-tab') === tabId);
    });

    document.querySelectorAll('.tab-panel').forEach(panel => {
      panel.classList.toggle('active', panel.id === `panel-${tabId}`);
    });
  }

  desktopTabs.forEach(t => {
    t.addEventListener('click', () => switchTab(t.getAttribute('data-tab')));
  });

  bottomTabs.forEach(t => {
    t.addEventListener('click', () => switchTab(t.getAttribute('data-tab')));
  });
}

// ─── API & Interfaces ──────────────────────────────────────────────
async function loadInterfaces() {
  try {
    const res = await fetch(`${API}/interfaces`);
    const data = await res.json();
    const select = document.getElementById('iface-select');
    if (!select) return;
    
    select.innerHTML = '';

    // data can be array directly or { interfaces: [...] }
    const ifaces = Array.isArray(data) ? data : (data.interfaces || []);

    if (ifaces && ifaces.length > 0) {
      ifaces.forEach(iface => {
        const opt = document.createElement('option');
        opt.value = iface.name;
        const ipStr = (iface.addresses && iface.addresses.length > 0) ? iface.addresses.join(', ') : (iface.ip || 'No IP');
        opt.textContent = `${iface.description || iface.name} [${ipStr}]`;
        select.appendChild(opt);
      });

      state.selectedIface = ifaces[0].name;
      select.value = state.selectedIface;
      await detectGateway();
    } else {
      select.innerHTML = '<option value="">Nenhuma interface encontrada (Requer Npcap)</option>';
      appendLog('warn', 'Nenhuma interface de rede detectada com IPv4.');
    }
  } catch (err) {
    appendLog('error', `Falha ao carregar interfaces: ${err.message}`);
  }
}

function onIfaceChange() {
  const select = document.getElementById('iface-select');
  state.selectedIface = select.value;
  detectGateway();
}

async function detectGateway() {
  try {
    // Check localinfo first
    if (state.selectedIface) {
      const res = await fetch(`${API}/localinfo?iface=${encodeURIComponent(state.selectedIface)}`);
      if (res.ok) {
        const data = await res.json();
        if (data.gw) {
          state.gatewayIP = data.gw;
          document.getElementById('gw-input').value = data.gw;
        }
        if (data.cidr) {
          state.cidr = data.cidr;
          document.getElementById('cidr-input').value = data.cidr;
          return;
        }
      }
    }

    // Fallback to /api/gateway
    const resGw = await fetch(`${API}/gateway`);
    const dataGw = await resGw.json();
    const gw = dataGw.gateway || dataGw.gateway_ip;
    if (gw) {
      state.gatewayIP = gw;
      document.getElementById('gw-input').value = gw;
      const parts = gw.split('.');
      if (parts.length === 4) {
        state.cidr = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
        document.getElementById('cidr-input').value = state.cidr;
      }
    }
  } catch (err) {
    appendLog('warn', `Auto-detecção de gateway indisponível.`);
  }
}

// ─── Subnet Scanning ───────────────────────────────────────────────
async function runScan() {
  if (state.isScanning) return;
  const cidr = document.getElementById('cidr-input').value.trim();
  if (!cidr) return;

  state.isScanning = true;
  updateStatusDisplay();

  const scanBtn = document.getElementById('btn-scan');
  scanBtn.disabled = true;

  try {
    const res = await fetch(`${API}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ iface: state.selectedIface, cidr: cidr })
    });
    const data = await res.json();
    // data can be array directly or { hosts: [...] }
    state.hosts = Array.isArray(data) ? data : (data.hosts || []);
    renderHosts();
  } catch (err) {
    appendLog('error', `Falha no escaneamento: ${err.message}`);
  } finally {
    state.isScanning = false;
    scanBtn.disabled = false;
    updateStatusDisplay();
  }
}

function renderHosts() {
  const tbody = document.getElementById('hosts-body');
  const countSpan = document.getElementById('host-count');
  if (!tbody) return;

  tbody.innerHTML = '';
  const dict = translations[currentLang];
  countSpan.textContent = `${state.hosts.length} ${dict.hostsDiscovered}`;

  if (state.hosts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--md-sys-color-outline);">${dict.noHostsFound}</td></tr>`;
    return;
  }

  state.hosts.forEach(h => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${h.ip}</strong></td>
      <td>${h.mac}</td>
      <td>${h.vendor || 'Unknown Host'}</td>
      <td>
        <button class="btn btn-tonal" style="padding: 4px 12px; font-size: 0.75rem;" onclick="selectTargetForSpoof('${h.ip}', '${h.mac}', 'mitm')">MITM</button>
        <button class="btn btn-tonal" style="padding: 4px 12px; font-size: 0.75rem; color: var(--md-sys-color-error);" onclick="selectTargetForSpoof('${h.ip}', '${h.mac}', 'dos')">DOS</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function selectTargetForSpoof(ip, mac, mode) {
  document.getElementById('target-ip').value = ip;
  document.getElementById('target-mac').value = mac;
  document.getElementById('attack-mode').value = mode;

  // Switch to Spoof Tab
  const spoofTab = document.querySelector('[data-tab="spoof"]');
  if (spoofTab) spoofTab.click();
}

// ─── ARP Spoofing Operations ───────────────────────────────────────
async function startSpoof() {
  const targetIP = document.getElementById('target-ip').value.trim();
  const targetMAC = document.getElementById('target-mac').value.trim();
  const gatewayIP = document.getElementById('gw-input').value.trim();
  const mode = document.getElementById('attack-mode').value;
  const rate = parseInt(document.getElementById('attack-rate').value, 10) || 1000;

  if (!targetIP || !gatewayIP) {
    appendLog('warn', 'Target IP and Gateway IP are required.');
    return;
  }

  try {
    const res = await fetch(`${API}/spoof/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        iface: state.selectedIface,
        target_ip: targetIP,
        gateway_ip: gatewayIP
      })
    });
    const data = await res.json();
    if (res.ok) {
      state.isSpoofing = true;
      toggleSpoofButtons(true);
      updateStatusDisplay();
    } else {
      appendLog('error', `Spoof operation failed: ${data.error}`);
    }
  } catch (err) {
    appendLog('error', `Connection error: ${err.message}`);
  }
}

async function stopSpoof() {
  try {
    const res = await fetch(`${API}/spoof/stop`, { method: 'POST' });
    if (res.ok) {
      state.isSpoofing = false;
      toggleSpoofButtons(false);
      updateStatusDisplay();
    }
  } catch (err) {
    appendLog('error', `Stop spoof error: ${err.message}`);
  }
}

function toggleSpoofButtons(active) {
  const startBtn = document.getElementById('btn-start-spoof');
  const stopBtn = document.getElementById('btn-stop-spoof');
  if (startBtn && stopBtn) {
    startBtn.style.display = active ? 'none' : 'inline-flex';
    stopBtn.style.display = active ? 'inline-flex' : 'none';
  }
}

// ─── Emergency Network Disruption (Kill All) ───────────────────────
async function killAll() {
  const dict = translations[currentLang];
  if (!confirm(dict.killConfirmMsg)) return;

  const gatewayIP = document.getElementById('gw-input').value.trim();
  try {
    const res = await fetch(`${API}/killall/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        iface: state.selectedIface,
        gateway_ip: gatewayIP
      })
    });
    if (res.ok) {
      state.isKillAll = true;
      document.getElementById('btn-kill-all').style.display = 'none';
      document.getElementById('btn-kill-stop').style.display = 'inline-flex';
      updateStatusDisplay();
    }
  } catch (err) {
    appendLog('error', `Kill-All error: ${err.message}`);
  }
}

async function killAllStop() {
  try {
    const res = await fetch(`${API}/killall/stop`, { method: 'POST' });
    if (res.ok) {
      state.isKillAll = false;
      document.getElementById('btn-kill-all').style.display = 'inline-flex';
      document.getElementById('btn-kill-stop').style.display = 'none';
      updateStatusDisplay();
    }
  } catch (err) {
    appendLog('error', `Stop kill-all error: ${err.message}`);
  }
}

// ─── SSE Stream Integrations (Logs & Traffic) ──────────────────────
function initSSE() {
  // Logs stream
  state.logEventSource = new EventSource(`${API}/logs`);
  state.logEventSource.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      appendLog(data.level, data.message, data.time);
    } catch (_) {
      appendLog('info', event.data);
    }
  };

  // Packets stream
  state.packetEventSource = new EventSource(`${API}/packets`);
  state.packetEventSource.onmessage = (event) => {
    try {
      const pkt = JSON.parse(event.data);
      handleIncomingPacket(pkt);
    } catch (_) {}
  };
}

function appendLog(level, message, timeStr) {
  const terminal = document.getElementById('log-terminal');
  if (!terminal) return;

  const now = timeStr || new Date().toTimeString().split(' ')[0];
  const row = document.createElement('div');
  row.className = 'log-entry';

  const cleanMsg = message.replace(/[\u{1F600}-\u{1F64F}\u{1F300}-\u{1F5FF}\u{1F680}-\u{1F6FF}\u{1F700}-\u{1F77F}\u{1F780}-\u{1F7FF}\u{1F800}-\u{1F8FF}\u{1F900}-\u{1F9FF}\u{1FA00}-\u{1FA6F}\u{1FA70}-\u{1FAFF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/gu, '');

  row.innerHTML = `
    <span class="log-time">[${now}]</span>
    <span class="log-level-${level}">[${level.toUpperCase()}]</span>
    <span>${cleanMsg}</span>
  `;

  terminal.appendChild(row);
  terminal.scrollTop = terminal.scrollHeight;
}

function clearLogs() {
  const terminal = document.getElementById('log-terminal');
  if (terminal) terminal.innerHTML = '';
}

function handleIncomingPacket(pkt) {
  state.packetCount++;
  const counter = document.getElementById('pkt-counter');
  if (counter) counter.textContent = state.packetCount;

  state.packets.unshift(pkt);
  if (state.packets.length > state.maxPackets) {
    state.packets.pop();
  }

  if (state.currentTab === 'traffic') {
    renderTrafficTable();
  }
}

function renderTrafficTable() {
  const tbody = document.getElementById('traffic-body');
  if (!tbody) return;

  const filter = state.protocolFilter;
  const filtered = filter === 'ALL' ? state.packets : state.packets.filter(p => p.protocol === filter);

  tbody.innerHTML = '';
  filtered.slice(0, 80).forEach(p => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${p.timestamp}</td>
      <td><span class="badge badge-${(p.protocol || '').toLowerCase()}">${p.protocol}</span></td>
      <td>${p.src}</td>
      <td>${p.dst}</td>
      <td>${p.length}B</td>
      <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${p.summary || ''}</td>
    `;
    tbody.appendChild(tr);
  });
}

function onProtocolFilterChange() {
  state.protocolFilter = document.getElementById('protocol-filter').value;
  renderTrafficTable();
}

function clearTraffic() {
  state.packets = [];
  renderTrafficTable();
}

function exportTrafficCSV() {
  if (state.packets.length === 0) return;
  let csv = 'Timestamp,Protocol,Source,Destination,Length,Summary\n';
  state.packets.forEach(p => {
    csv += `"${p.timestamp}","${p.protocol}","${p.src}","${p.dst}","${p.length}","${(p.summary || '').replace(/"/g, '""')}"\n`;
  });

  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `arpanet_traffic_${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Status Pill Logic ─────────────────────────────────────────────
function updateStatusDisplay() {
  const dot = document.getElementById('status-dot');
  const text = document.getElementById('status-text');
  const dict = translations[currentLang];
  if (!dot || !text) return;

  dot.classList.remove('active', 'scanning');

  if (state.isKillAll) {
    dot.classList.add('active');
    text.textContent = dict.statusKillAll;
  } else if (state.isSpoofing) {
    dot.classList.add('active');
    text.textContent = dict.statusSpoofing;
  } else if (state.isScanning) {
    dot.classList.add('scanning');
    text.textContent = dict.statusScanning;
  } else {
    text.textContent = dict.statusIdle;
  }
}
