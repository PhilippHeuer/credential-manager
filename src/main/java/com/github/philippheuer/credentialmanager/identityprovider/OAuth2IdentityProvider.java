package com.github.philippheuer.credentialmanager.identityprovider;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.philippheuer.credentialmanager.domain.IdentityProvider;
import com.github.philippheuer.credentialmanager.domain.OAuth2Credential;
import com.github.philippheuer.credentialmanager.util.ProxyHelper;
import lombok.SneakyThrows;
import okhttp3.*;
import org.apache.commons.lang3.exception.ContextedRuntimeException;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URLEncoder;
import java.util.*;
import java.util.stream.Collectors;

/**
 * OAuth2 Identity Provider
 */
public abstract class OAuth2IdentityProvider extends IdentityProvider {

    /**
     * OAuth Client Id
     */
    protected String clientId;

    /**
     * OAuth Client Secret
     */
    protected String clientSecret;

    /**
     * Auth Endpoint
     */
    protected String authUrl;

    /**
     * Token Endpoint
     */
    protected String tokenUrl;

    /**
     * Redirect URL
     */
    protected String redirectUrl;

    /**
     * Scope Separator
     */
    protected String scopeSeperator = " ";

    /**
     * Response Type
     */
    protected String responseType = "code";

    /**
     * Token Endpoint Post Type: QUERY or BODY
     */
    protected String tokenEndpointPostType = "QUERY";

    /**
     * Constructor
     *
     * @param providerName Provider Name
     * @param providerType Provider Type
     * @param clientId     Client ID
     * @param clientSecret Client Secret
     * @param authUrl      Auth URL
     * @param tokenUrl     Token URL
     * @param redirectUrl  Redirect URL
     */
    public OAuth2IdentityProvider(String providerName, String providerType, String clientId, String clientSecret, String authUrl, String tokenUrl, String redirectUrl) {
        this.providerName = providerName;
        this.providerType = providerType;
        this.clientId = clientId == null ? "" : clientId;
        this.clientSecret = clientSecret == null ? "" : clientSecret;
        this.authUrl = authUrl;
        this.tokenUrl = tokenUrl;
        this.redirectUrl = redirectUrl;
    }

    /**
     * Get Authentication Url
     *
     * @param scopes requested scopes
     * @param state  state - csrf protection
     * @return url
     */
    public String getAuthenticationUrl(List<Object> scopes, String state) {
        return getAuthenticationUrl(this.redirectUrl, scopes, state);
    }

    /**
     * Get Authentication Url
     *
     * @param redirectUrl overwrite the redirect url with a custom one
     * @param scopes      requested scopes
     * @param state       state - csrf protection
     * @return url
     */
    @SneakyThrows
    public String getAuthenticationUrl(String redirectUrl, List<Object> scopes, String state) {
        if (state == null) {
            state = this.providerName + "|" + UUID.randomUUID();
        }
        return String.format("%s?response_type=%s&client_id=%s&redirect_uri=%s&scope=%s&state=%s", authUrl, URLEncoder.encode(responseType, "UTF-8"), URLEncoder.encode(clientId, "UTF-8"), URLEncoder.encode(redirectUrl, "UTF-8"), String.join(scopeSeperator, scopes.stream().map(s -> s.toString()).collect(Collectors.toList())), URLEncoder.encode(state, "UTF-8"));
    }

    /**
     * Get Access Token
     */
    public OAuth2Credential getCredentialByCode(String code) {
        // request access token
        OkHttpClient client = new OkHttpClient();
        ObjectMapper objectMapper = new ObjectMapper();

        // use system proxy, if specified
        if (ProxyHelper.getSystemHttpProxyPort() != null && ProxyHelper.getSystemHttpProxyPort() > 0) {
            Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(ProxyHelper.getSystemHttpProxyHost(), ProxyHelper.getSystemHttpProxyPort()));
            client = client.newBuilder().proxy(proxy).build();
        }

        try {
            Request request;

            if (tokenEndpointPostType.equalsIgnoreCase("QUERY")) {
                HttpUrl.Builder urlBuilder = HttpUrl.parse(this.tokenUrl).newBuilder();
                urlBuilder.addQueryParameter("client_id", this.clientId);
                urlBuilder.addQueryParameter("client_secret", this.clientSecret);
                urlBuilder.addQueryParameter("code", code);
                urlBuilder.addQueryParameter("grant_type", "authorization_code");
                urlBuilder.addQueryParameter("redirect_uri", this.redirectUrl);

                request = new Request.Builder()
                        .url(urlBuilder.build().toString())
                        .post(RequestBody.create(null, new byte[]{}))
                        .build();
            } else if (tokenEndpointPostType.equalsIgnoreCase("BODY")) {
                RequestBody requestBody = new MultipartBody.Builder()
                        .setType(MultipartBody.FORM)
                        .addFormDataPart("client_id", this.clientId)
                        .addFormDataPart("client_secret", this.clientSecret)
                        .addFormDataPart("code", code)
                        .addFormDataPart("grant_type", "authorization_code")
                        .addFormDataPart("redirect_uri", this.redirectUrl)
                        .build();

                request = new Request.Builder()
                        .url(this.tokenUrl)
                        .post(requestBody)
                        .build();
            } else {
                throw new UnsupportedOperationException("Unknown tokenEndpointPostType: " + tokenEndpointPostType);
            }

            Response response = client.newCall(request).execute();
            String responseBody = response.body().string();
            if (response.isSuccessful()) {
                Map<String, Object> resultMap = objectMapper.readValue(responseBody, new TypeReference<HashMap<String, Object>>() {});

                return new OAuth2Credential(this.providerName, (String) resultMap.get("access_token"), (String) resultMap.get("refresh_token"), null, null, (Integer) resultMap.get("expires_in"), null);
            } else {
                throw new ContextedRuntimeException("getCredentialByCode request failed!")
                        .addContextValue("requestUrl", request.url())
                        .addContextValue("requestHeaders", request.headers())
                        .addContextValue("requestBody", request.body())
                        .addContextValue("responseCode", response.code())
                        .addContextValue("responseBody", responseBody);
            }

        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Get Access Token
     */
    public OAuth2Credential getCredentialByUsernameAndPassword(String username, String password) {
        // request access token
        OkHttpClient client = new OkHttpClient();
        ObjectMapper objectMapper = new ObjectMapper();

        // use system proxy, if specified
        if (ProxyHelper.getSystemHttpProxyPort() != null && ProxyHelper.getSystemHttpProxyPort() > 0) {
            Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(ProxyHelper.getSystemHttpProxyHost(), ProxyHelper.getSystemHttpProxyPort()));
            client = client.newBuilder().proxy(proxy).build();
        }

        try {
            Request request;

            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes()));

            if (tokenEndpointPostType.equalsIgnoreCase("QUERY")) {
                HttpUrl.Builder urlBuilder = HttpUrl.parse(this.tokenUrl).newBuilder();
                urlBuilder.addQueryParameter("grant_type", "password");
                urlBuilder.addQueryParameter("username", username);
                urlBuilder.addQueryParameter("password", password);

                request = new Request.Builder()
                        .url(urlBuilder.build().toString())
                        .headers(Headers.of(headers))
                        .post(RequestBody.create(null, new byte[]{}))
                        .build();
            } else if (tokenEndpointPostType.equalsIgnoreCase("BODY")) {
                HttpUrl.Builder urlBuilder = HttpUrl.parse("http://localhost").newBuilder();
                urlBuilder.addQueryParameter("grant_type", "password");
                urlBuilder.addQueryParameter("username", username);
                urlBuilder.addQueryParameter("password", password);
                RequestBody requestBody = RequestBody.create(MediaType.parse("application/x-www-form-urlencoded"), urlBuilder.toString().replace("http://localhost/?", "").getBytes());

                request = new Request.Builder()
                        .url(this.tokenUrl)
                        .headers(Headers.of(headers))
                        .post(requestBody)
                        .build();
            } else {
                throw new UnsupportedOperationException("Unknown tokenEndpointPostType: " + tokenEndpointPostType);
            }

            Response response = client.newCall(request).execute();
            String responseBody = response.body().string();
            if (response.isSuccessful()) {
                Map<String, Object> resultMap = objectMapper.readValue(responseBody, new TypeReference<HashMap<String, Object>>() {});

                return new OAuth2Credential(this.providerName, (String) resultMap.get("access_token"), (String) resultMap.get("refresh_token"), null, null, (Integer) resultMap.get("expires_in"), null);
            } else {
                throw new ContextedRuntimeException("getCredentialByUsernameAndPassword request failed!")
                        .addContextValue("requestUrl", request.url())
                        .addContextValue("requestHeaders", request.headers())
                        .addContextValue("requestBody", request.body())
                        .addContextValue("responseCode", response.code())
                        .addContextValue("responseBody", responseBody);
            }

        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Get Token Information
     *
     * @param credential OAuth2 Credential
     * @return Token Information
     */
    abstract public Optional<OAuth2Credential> getAdditionalCredentialInformation(OAuth2Credential credential);

}
