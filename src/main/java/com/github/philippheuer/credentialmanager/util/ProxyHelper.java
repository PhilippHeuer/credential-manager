package com.github.philippheuer.credentialmanager.util;

import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.Nullable;

import java.net.InetSocketAddress;
import java.net.Proxy;

/**
 * Tries to use the system proxy like any other normal sane app ...
 */
public class ProxyHelper {

    /**
     * automatically detects the proxy from env variables
     *
     * @return the https proxy (env), http proxy (env) or null in this order
     */
    @Nullable
    public static Proxy selectProxy() {
        // HTTPS
        if (!StringUtils.isEmpty(ProxyHelper.getSystemHttpsProxyHost()) && ProxyHelper.getSystemHttpsProxyPort() > 0) {
            return new Proxy(Proxy.Type.HTTP, new InetSocketAddress(ProxyHelper.getSystemHttpsProxyHost(), ProxyHelper.getSystemHttpsProxyPort()));
        }

        // HTTP
        if (!StringUtils.isEmpty(ProxyHelper.getSystemHttpProxyHost()) && ProxyHelper.getSystemHttpProxyPort() > 0) {
            return new Proxy(Proxy.Type.HTTP, new InetSocketAddress(ProxyHelper.getSystemHttpProxyHost(), ProxyHelper.getSystemHttpProxyPort()));
        }

        return null;
    }

    public static String getSystemHttpProxyHost() {
        return getProxyHostByKey("http_proxy") != null ? getProxyHostByKey("http_proxy") : getProxyHostByKey("HTTP_PROXY");
    }

    public static Integer getSystemHttpProxyPort() {
        return getProxyPortByKey("http_proxy") != null ? getProxyPortByKey("http_proxy") : getProxyPortByKey("HTTP_PROXY");
    }

    public static String getSystemHttpsProxyHost() {
        return getProxyHostByKey("https_proxy") != null ? getProxyHostByKey("https_proxy") : getProxyHostByKey("HTTPS_PROXY");
    }

    public static Integer getSystemHttpsProxyPort() {
        return getProxyPortByKey("https_proxy") != null ? getProxyPortByKey("https_proxy") : getProxyPortByKey("HTTPS_PROXY");
    }

    private static String getProxyHostByKey(String propertyName) {
        String httpProxy = System.getenv(propertyName);
        if (httpProxy == null) {
            return null;
        }

        String[] proxyInfo = httpProxy.replace("http://", "").replace("https://", "").split(":");
        if (proxyInfo.length == 2) {
            return proxyInfo[0];
        } else {
            return null;
        }
    }

    private static Integer getProxyPortByKey(String propertyName) {
        String httpProxy = System.getenv(propertyName);
        if (httpProxy == null) {
            return null;
        }

        String[] proxyInfo = httpProxy.replace("http://", "").replace("https://", "").split(":");
        if (proxyInfo.length == 2) {
            return Integer.parseInt(proxyInfo[1]);
        } else {
            return null;
        }
    }

}
