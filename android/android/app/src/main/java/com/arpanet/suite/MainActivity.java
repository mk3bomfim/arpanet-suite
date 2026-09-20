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
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.List;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView webView = this.bridge.getWebView();
        webView.addJavascriptInterface(new NativeNetworkBridge(this), "AndroidBridge");
    }

    public static class NativeNetworkBridge {
        private final Context context;

        public NativeNetworkBridge(Context ctx) {
            this.context = ctx;
        }

        @JavascriptInterface
        public String getDeviceInfo() {
            String manufacturer = Build.MANUFACTURER;
            String model = Build.MODEL;
            String brand = Build.BRAND;
            String release = Build.VERSION.RELEASE;
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
            String gateway = "192.168.1.1";
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
                    if (dhcp != null && (gateway.equals("192.168.1.1") || gateway.equals("0.0.0.0"))) {
                        if (dhcp.gateway != 0) {
                            gateway = intToIp(dhcp.gateway);
                        }
                        if (dhcp.netmask != 0 && netmask.equals("255.255.255.0")) {
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
}
