package com.github.philippheuer.credentialmanager.util;

/**
 * Tries to use the system proxy like any other normal sane app ...
 */
public class ProxyHelper {

    public static String getSystemHttpProxyHost() {
        return getProxyHostByProperty("http_proxy");
    }

    public static Integer getSystemHttpProxyPort() {
        return getProxyPortByProperty("http_proxy");
    }

    public static String getSystemHttpsProxyHost() {
        return getProxyHostByProperty("https_proxy");
    }

    public static Integer getSystemHttpsProxyPort() {
        return getProxyPortByProperty("https_proxy");
    }

    private static String getProxyHostByProperty(String propertyName) {
        String httpProxy = System.getProperty("http_proxy", "");
        String[] proxyInfo = httpProxy.replace("http://", "").replace("https://", "").split(":");

        if (proxyInfo.length == 2) {
            return proxyInfo[0];
        } else {
            return null;
        }
    }

    private static Integer getProxyPortByProperty(String propertyName) {
        String httpProxy = System.getProperty("http_proxy", "");
        String[] proxyInfo = httpProxy.replace("http://", "").replace("https://", "").split(":");

        if (proxyInfo.length == 2) {
            return Integer.parseInt(proxyInfo[1]);
        } else {
            return null;
        }
    }

}
