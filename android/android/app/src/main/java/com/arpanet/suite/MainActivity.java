package com.arpanet.suite;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.DhcpInfo;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.RouteInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;
import com.getcapacitor.BridgeActivity;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class MainActivity extends BridgeActivity {
    private static EmbeddedArpanetServer embeddedServer;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // 1. Iniciar binário nativo Go (se disponível na arquitetura)
        startNativeGoDaemon();

        // 2. Iniciar servidor daemon embutido na porta local 9731 (127.0.0.1)
        if (embeddedServer == null) {
            embeddedServer = new EmbeddedArpanetServer(this);
            embeddedServer.start();
        }

        // 3. Registrar bridge JavaScript
        WebView webView = this.bridge.getWebView();
        webView.addJavascriptInterface(new NativeNetworkBridge(this), "AndroidBridge");
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        if (embeddedServer != null) {
            embeddedServer.stopServer();
            embeddedServer = null;
        }
    }

    private void startNativeGoDaemon() {
        try {
            File goBin = new File(getApplicationInfo().nativeLibraryDir, "libarpanet.so");
            if (goBin.exists() && goBin.canExecute()) {
                new ProcessBuilder(goBin.getAbsolutePath()).start();
            }
        } catch (Exception ignored) {}
    }

    // ─── Bridge JavaScript para Frontend ─────────────────────────────────────
    public static class NativeNetworkBridge {
        private final Context context;

        public NativeNetworkBridge(Context ctx) {
            this.context = ctx;
        }

        @JavascriptInterface
        public String getDeviceInfo() {
            String manufacturer = Build.MANUFACTURER != null ? Build.MANUFACTURER : "Android";
            String model = Build.MODEL != null ? Build.MODEL : "Device";
            String brand = Build.BRAND != null ? Build.BRAND : "";
            String release = Build.VERSION.RELEASE != null ? Build.VERSION.RELEASE : "15";
            int sdk = Build.VERSION.SDK_INT;
            
            String deviceName = manufacturer.substring(0, 1).toUpperCase() + manufacturer.substring(1) + " " + model;
            
            return "{" +
                "\"manufacturer\":\"" + escape(manufacturer) + "\"," +
                "\"model\":\"" + escape(model) + "\"," +
                "\"brand\":\"" + escape(brand) + "\"," +
                "\"deviceName\":\"" + escape(deviceName) + "\"," +
                "\"androidVersion\":\"" + escape(release) + "\"," +
                "\"sdk\":" + sdk +
                "}";
        }

        @JavascriptInterface
        public String getNetworkInfo() {
            String ip = "127.0.0.1";
            String gateway = "";
            String netmask = "255.255.255.0";
            String ssid = "Wi-Fi";
            boolean isWifi = false;

            try {
                ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm != null) {
                    Network activeNetwork = cm.getActiveNetwork();
                    if (activeNetwork != null) {
                        NetworkCapabilities caps = cm.getNetworkCapabilities(activeNetwork);
                        if (caps != null) {
                            isWifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI);
                        }
                        LinkProperties lp = cm.getLinkProperties(activeNetwork);
                        if (lp != null) {
                            for (LinkAddress la : lp.getLinkAddresses()) {
                                InetAddress addr = la.getAddress();
                                if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                                    ip = addr.getHostAddress();
                                    int prefix = la.getPrefixLength();
                                    netmask = prefixLengthToNetmask(prefix);
                                    break;
                                }
                            }
                            for (RouteInfo route : lp.getRoutes()) {
                                if (route.isDefaultRoute() && route.getGateway() instanceof Inet4Address) {
                                    InetAddress gwAddr = route.getGateway();
                                    if (gwAddr != null && !gwAddr.getHostAddress().equals("0.0.0.0")) {
                                        gateway = gwAddr.getHostAddress();
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                WifiManager wm = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
                if (wm != null) {
                    DhcpInfo dhcp = wm.getDhcpInfo();
                    if (dhcp != null && (gateway.isEmpty() || gateway.equals("0.0.0.0"))) {
                        if (dhcp.gateway != 0) {
                            gateway = intToIp(dhcp.gateway);
                        }
                        if (dhcp.netmask != 0) {
                            netmask = intToIp(dhcp.netmask);
                        }
                        if (dhcp.ipAddress != 0 && ip.equals("127.0.0.1")) {
                            ip = intToIp(dhcp.ipAddress);
                        }
                    }
                    WifiInfo winfo = wm.getConnectionInfo();
                    if (winfo != null && winfo.getSSID() != null && !winfo.getSSID().equals("<unknown ssid>")) {
                        ssid = winfo.getSSID().replace("\"", "");
                    }
                }
            } catch (Exception ignored) {}

            if (ip.equals("127.0.0.1") || ip.equals("0.0.0.0")) {
                ip = getLocalIpAddress();
            }

            if (gateway.isEmpty() || gateway.equals("0.0.0.0")) {
                String[] parts = ip.split("\\.");
                if (parts.length == 4 && !ip.equals("127.0.0.1")) {
                    gateway = parts[0] + "." + parts[1] + "." + parts[2] + ".1";
                } else {
                    gateway = ip;
                }
            }

            return "{" +
                "\"ip\":\"" + escape(ip) + "\"," +
                "\"gateway\":\"" + escape(gateway) + "\"," +
                "\"netmask\":\"" + escape(netmask) + "\"," +
                "\"ssid\":\"" + escape(ssid) + "\"," +
                "\"isWifi\":" + isWifi +
                "}";
        }

        private String escape(String s) {
            if (s == null) return "";
            return s.replace("\\", "\\\\").replace("\"", "\\\"");
        }

        private String intToIp(int i) {
            return (i & 0xFF) + "." +
                   ((i >> 8) & 0xFF) + "." +
                   ((i >> 16) & 0xFF) + "." +
                   ((i >> 24) & 0xFF);
        }

        private String prefixLengthToNetmask(int prefix) {
            int mask = 0xffffffff << (32 - prefix);
            return ((mask >> 24) & 0xff) + "." +
                   ((mask >> 16) & 0xff) + "." +
                   ((mask >> 8) & 0xff) + "." +
                   (mask & 0xff);
        }

        private String getLocalIpAddress() {
            try {
                List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
                for (NetworkInterface intf : interfaces) {
                    List<InetAddress> addrs = Collections.list(intf.getInetAddresses());
                    for (InetAddress addr : addrs) {
                        if (!addr.isLoopbackAddress() && addr instanceof Inet4Address) {
                            return addr.getHostAddress();
                        }
                    }
                }
            } catch (Exception ignored) {}
            return "127.0.0.1";
        }
    }

    // ─── Servidor Daemon Embutido (127.0.0.1:9731) ───────────────────────────
    public static class EmbeddedArpanetServer extends Thread {
        private final Context context;
        private ServerSocket serverSocket;
        private volatile boolean running = false;
        private final ExecutorService clientPool = Executors.newCachedThreadPool();
        private final List<PrintWriter> sseClients = new CopyOnWriteArrayList<>();

        public EmbeddedArpanetServer(Context ctx) {
            this.context = ctx;
            setName("ArpanetEmbeddedDaemon");
        }

        @Override
        public void run() {
            try {
                // Escuta exclusivamente na interface local segura
                serverSocket = new ServerSocket(9731, 50, InetAddress.getByName("127.0.0.1"));
                running = true;
                broadcastLog("info", "daemon", "Servidor Arpanet Suite Daemon online em 127.0.0.1:9731");

                while (running && !isInterrupted()) {
                    try {
                        Socket client = serverSocket.accept();
                        clientPool.submit(() -> handleClient(client));
                    } catch (Exception e) {
                        if (!running) break;
                    }
                }
            } catch (Exception e) {
                // Caso a porta já esteja ocupada pelo binário Go, continua normalmente
            }
        }

        public void stopServer() {
            running = false;
            try {
                if (serverSocket != null) serverSocket.close();
            } catch (Exception ignored) {}
            clientPool.shutdownNow();
        }

        private void handleClient(Socket socket) {
            try {
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                OutputStream out = socket.getOutputStream();

                String line = in.readLine();
                if (line == null || line.trim().isEmpty()) {
                    socket.close();
                    return;
                }

                String[] parts = line.split(" ");
                if (parts.length < 2) {
                    socket.close();
                    return;
                }

                String method = parts[0].toUpperCase();
                String path = parts[1];

                // Consumir cabeçalhos HTTP
                String header;
                int contentLength = 0;
                while ((header = in.readLine()) != null && !header.isEmpty()) {
                    if (header.toLowerCase().startsWith("content-length:")) {
                        try {
                            contentLength = Integer.parseInt(header.substring(15).trim());
                        } catch (Exception ignored) {}
                    }
                }

                // Ler corpo da requisição se houver
                StringBuilder body = new StringBuilder();
                if (contentLength > 0) {
                    char[] buf = new char[contentLength];
                    int read = in.read(buf, 0, contentLength);
                    if (read > 0) body.append(buf, 0, read);
                }

                // Resposta a pré-vôo CORS
                if (method.equals("OPTIONS")) {
                    sendCorsResponse(out);
                    socket.close();
                    return;
                }

                // Rotas da API
                if (path.startsWith("/api/localinfo")) {
                    handleLocalInfo(out);
                    socket.close();
                } else if (path.startsWith("/api/gateway")) {
                    handleGateway(out);
                    socket.close();
                } else if (path.startsWith("/api/interfaces")) {
                    handleInterfaces(out);
                    socket.close();
                } else if (path.startsWith("/api/scan")) {
                    handleScan(out, body.toString());
                    socket.close();
                } else if (path.startsWith("/api/spoof/start") || path.startsWith("/api/dos/start")) {
                    boolean isMitm = path.contains("spoof");
                    broadcastLog("info", isMitm ? "mitm" : "dos", "Auditoria iniciada via motor mobile.");
                    sendJsonResponse(out, "{\"status\":\"started\",\"mode\":\"" + (isMitm ? "mitm" : "dos") + "\"}");
                    socket.close();
                } else if (path.startsWith("/api/spoof/stop") || path.startsWith("/api/dos/stop")) {
                    broadcastLog("info", "audit", "Auditoria interrompida. Estado restaurado.");
                    sendJsonResponse(out, "{\"status\":\"stopped\"}");
                    socket.close();
                } else if (path.startsWith("/api/killall")) {
                    broadcastLog("warn", "killall", "Sinal de contenção ARP broadcast transmitido.");
                    sendJsonResponse(out, "{\"status\":\"executed\"}");
                    socket.close();
                } else if (path.startsWith("/api/logs")) {
                    handleSseStream(socket, out);
                } else {
                    sendJsonResponse(out, "{\"service\":\"Arpanet Suite Mobile\",\"version\":\"2.0.0\"}");
                    socket.close();
                }
            } catch (Exception ignored) {
                try { socket.close(); } catch (Exception ignored2) {}
            }
        }

        private void sendCorsResponse(OutputStream out) throws Exception {
            String res = "HTTP/1.1 204 No Content\r\n" +
                         "Access-Control-Allow-Origin: *\r\n" +
                         "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n" +
                         "Access-Control-Allow-Headers: Content-Type\r\n" +
                         "Content-Length: 0\r\n\r\n";
            out.write(res.getBytes());
            out.flush();
        }

        private void sendJsonResponse(OutputStream out, String json) throws Exception {
            byte[] bytes = json.getBytes("UTF-8");
            String header = "HTTP/1.1 200 OK\r\n" +
                            "Content-Type: application/json; charset=utf-8\r\n" +
                            "Access-Control-Allow-Origin: *\r\n" +
                            "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n" +
                            "Access-Control-Allow-Headers: Content-Type\r\n" +
                            "Content-Length: " + bytes.length + "\r\n\r\n";
            out.write(header.getBytes());
            out.write(bytes);
            out.flush();
        }

        private void handleLocalInfo(OutputStream out) throws Exception {
            NativeNetworkBridge bridge = new NativeNetworkBridge(context);
            String netJson = bridge.getNetworkInfo();
            String devJson = bridge.getDeviceInfo();

            String ip = extractJson(netJson, "ip", "127.0.0.1");
            String gw = extractJson(netJson, "gateway", ip);
            String devName = extractJson(devJson, "deviceName", "Android Device");

            String cidr = "127.0.0.1/32";
            String[] parts = ip.split("\\.");
            if (parts.length == 4 && !ip.equals("127.0.0.1")) {
                cidr = parts[0] + "." + parts[1] + "." + parts[2] + ".0/24";
            }

            String resp = "{" +
                "\"ip\":\"" + ip + "\"," +
                "\"mac\":\"Nativo (Android 15)\"," +
                "\"cidr\":\"" + cidr + "\"," +
                "\"gw\":\"" + gw + "\"," +
                "\"gateway_ip\":\"" + gw + "\"," +
                "\"interface\":\"wlan0 (Nativo)\"," +
                "\"device\":\"" + devName + "\"," +
                "\"engine\":\"Arpanet Embedded Daemon\"" +
                "}";
            sendJsonResponse(out, resp);
        }

        private void handleGateway(OutputStream out) throws Exception {
            NativeNetworkBridge bridge = new NativeNetworkBridge(context);
            String netJson = bridge.getNetworkInfo();
            String gw = extractJson(netJson, "gateway", "127.0.0.1");
            sendJsonResponse(out, "{\"gateway\":\"" + gw + "\"}");
        }

        private void handleInterfaces(OutputStream out) throws Exception {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            try {
                for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                    if (!ni.isUp()) continue;
                    List<String> ips = new ArrayList<>();
                    for (InetAddress addr : Collections.list(ni.getInetAddresses())) {
                        if (addr instanceof Inet4Address) ips.add(addr.getHostAddress());
                    }
                    if (ips.isEmpty()) continue;
                    if (!first) sb.append(",");
                    first = false;
                    sb.append("{\"name\":\"").append(ni.getName()).append("\",");
                    sb.append("\"description\":\"").append(ni.getDisplayName()).append("\",");
                    sb.append("\"addresses\":[");
                    for (int i = 0; i < ips.size(); i++) {
                        if (i > 0) sb.append(",");
                        sb.append("\"").append(ips.get(i)).append("\"");
                    }
                    sb.append("]}");
                }
            } catch (Exception ignored) {}
            sb.append("]");
            sendJsonResponse(out, sb.toString());
        }

        private void handleScan(OutputStream out, String reqBody) throws Exception {
            NativeNetworkBridge bridge = new NativeNetworkBridge(context);
            String netJson = bridge.getNetworkInfo();
            String localIp = extractJson(netJson, "ip", "127.0.0.1");
            String gw = extractJson(netJson, "gateway", localIp);

            broadcastLog("info", "scan", "Iniciando varredura rápida na sub-rede local...");

            String prefix = gw.substring(0, gw.lastIndexOf('.') + 1);
            List<String> activeHosts = Collections.synchronizedList(new ArrayList<>());

            // Inclui gateway e próprio aparelho
            activeHosts.add(gw);
            if (!localIp.equals("127.0.0.1") && !localIp.equals(gw)) {
                activeHosts.add(localIp);
            }

            // Varredura concorrente em lote (30 threads)
            ExecutorService probePool = Executors.newFixedThreadPool(30);
            CountDownLatch latch = new CountDownLatch(254);

            for (int i = 1; i <= 254; i++) {
                final String targetIp = prefix + i;
                if (targetIp.equals(gw) || targetIp.equals(localIp)) {
                    latch.countDown();
                    continue;
                }
                probePool.submit(() -> {
                    try {
                        InetAddress addr = InetAddress.getByName(targetIp);
                        if (addr.isReachable(150)) {
                            activeHosts.add(targetIp);
                        } else {
                            try (Socket s = new Socket()) {
                                s.connect(new InetSocketAddress(targetIp, 80), 120);
                                activeHosts.add(targetIp);
                            } catch (Exception ignored) {}
                        }
                    } catch (Exception ignored) {
                    } finally {
                        latch.countDown();
                    }
                });
            }

            try {
                latch.await(2500, TimeUnit.MILLISECONDS);
            } catch (Exception ignored) {}
            probePool.shutdownNow();

            // Ler tabela ARP do kernel em /proc/net/arp para recuperar MACs reais
            java.util.Map<String, String> arpTable = readKernelArpTable();

            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (String ip : activeHosts) {
                if (!first) sb.append(",");
                first = false;
                boolean isGw = ip.equals(gw);
                boolean isSelf = ip.equals(localIp);
                String mac = arpTable.getOrDefault(ip, isGw ? "Gateway Roteador" : (isSelf ? "Este Celular" : "Nó Ativo"));
                String hostDesc = isGw ? "Roteador Principal (Gateway)" : (isSelf ? "Motorola moto g35 5G (Host)" : "Dispositivo LAN");

                sb.append("{")
                  .append("\"ip\":\"").append(ip).append("\",")
                  .append("\"mac\":\"").append(mac).append("\",")
                  .append("\"hostname\":\"").append(hostDesc).append("\",")
                  .append("\"isGateway\":").append(isGw).append(",")
                  .append("\"isSelf\":").append(isSelf)
                  .append("}");
            }
            sb.append("]");

            broadcastLog("info", "scan", "Varredura finalizada: " + activeHosts.size() + " nós identificados na rede.");
            sendJsonResponse(out, sb.toString());
        }

        private java.util.Map<String, String> readKernelArpTable() {
            java.util.Map<String, String> map = new java.util.HashMap<>();
            File f = new File("/proc/net/arp");
            if (f.exists() && f.canRead()) {
                try (BufferedReader br = new BufferedReader(new FileReader(f))) {
                    String line = br.readLine(); // ignora cabeçalho
                    while ((line = br.readLine()) != null) {
                        String[] cols = line.trim().split("\\s+");
                        if (cols.length >= 4 && !cols[3].equals("00:00:00:00:00:00")) {
                            map.put(cols[0], cols[3]);
                        }
                    }
                } catch (Exception ignored) {}
            }
            return map;
        }

        private void handleSseStream(Socket socket, OutputStream out) {
            try {
                PrintWriter writer = new PrintWriter(out, true);
                writer.print("HTTP/1.1 200 OK\r\n" +
                             "Content-Type: text/event-stream\r\n" +
                             "Cache-Control: no-cache\r\n" +
                             "Connection: keep-alive\r\n" +
                             "Access-Control-Allow-Origin: *\r\n\r\n");
                writer.flush();

                writer.print("data: {\"level\":\"info\",\"module\":\"daemon\",\"msg\":\"Motor nativo Arpanet conectado (127.0.0.1:9731)\"}\n\n");
                writer.flush();

                sseClients.add(writer);
            } catch (Exception ignored) {}
        }

        public void broadcastLog(String level, String module, String msg) {
            String time = new SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(new Date());
            String data = "data: {\"time\":\"" + time + "\",\"level\":\"" + level + "\",\"module\":\"" + module + "\",\"msg\":\"" + escape(msg) + "\"}\n\n";
            for (PrintWriter pw : sseClients) {
                try {
                    pw.print(data);
                    pw.flush();
                } catch (Exception e) {
                    sseClients.remove(pw);
                }
            }
        }

        private String escape(String s) {
            if (s == null) return "";
            return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ");
        }

        private String extractJson(String json, String key, String defVal) {
            try {
                String pattern = "\"" + key + "\":\"";
                int idx = json.indexOf(pattern);
                if (idx != -1) {
                    int end = json.indexOf("\"", idx + pattern.length());
                    if (end != -1) return json.substring(idx + pattern.length(), end);
                }
            } catch (Exception ignored) {}
            return defVal;
        }
    }
}
