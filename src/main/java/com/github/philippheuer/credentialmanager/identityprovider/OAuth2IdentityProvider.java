package com.github.philippheuer.credentialmanager.identityprovider;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import com.github.philippheuer.credentialmanager.domain.Credential;
import com.github.philippheuer.credentialmanager.domain.IdentityProvider;
import com.github.philippheuer.credentialmanager.domain.OAuth2Credential;
import com.github.philippheuer.credentialmanager.util.ProxyHelper;
import lombok.SneakyThrows;
import okhttp3.FormBody;
import okhttp3.Headers;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.logging.HttpLoggingInterceptor;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ContextedRuntimeException;

import java.net.Proxy;
import java.net.URLEncoder;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * OAuth2 Identity Provider
 */
@Slf4j
public abstract class OAuth2IdentityProvider extends IdentityProvider {
    protected static final ObjectMapper OBJECTMAPPER = new ObjectMapper();
    protected OkHttpClient httpClient = new OkHttpClient();


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
        this(providerName, providerType, clientId, clientSecret, authUrl, tokenUrl, redirectUrl, ProxyHelper.selectProxy());
    }

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
     * @param proxy HTTP Proxy
     */
    public OAuth2IdentityProvider(String providerName, String providerType, String clientId, String clientSecret, String authUrl, String tokenUrl, String redirectUrl, Proxy proxy) {
        this.providerName = providerName;
        this.providerType = providerType;
        this.clientId = clientId == null ? "" : clientId;
        this.clientSecret = clientSecret == null ? "" : clientSecret;
        this.authUrl = authUrl;
        this.tokenUrl = tokenUrl;
        this.redirectUrl = redirectUrl;

        if (proxy != null) {
            httpClient = httpClient.newBuilder().proxy(proxy).build();
        }
    }

    /**
     * enables a logging interceptor to investigate issues
     */
    public void enableLoggingInterceptor() {
        HttpLoggingInterceptor logging = new HttpLoggingInterceptor();
        logging.setLevel(HttpLoggingInterceptor.Level.BODY);
        httpClient = httpClient.newBuilder().addInterceptor(logging).build();
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
        Map<String, String> parameters = new HashMap<>();
        parameters.put("client_id", this.clientId);
        parameters.put("client_secret", this.clientSecret);
        parameters.put("grant_type", "authorization_code");
        parameters.put("code", code);
        parameters.put("redirect_uri", this.redirectUrl);

        try {
            Request request = getTokenRequest(parameters, Collections.emptyMap());

            Response response = httpClient.newCall(request).execute();
            String responseBody = response.body().string();
            if (response.isSuccessful()) {
                Map<String, Object> resultMap = OBJECTMAPPER.readValue(responseBody, new TypeReference<HashMap<String, Object>>() {});

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
        return getScopedCredentialByUsernameAndPassword(username, password, null);
    }

    /**
     * Get Access Token
     */
    public OAuth2Credential getScopedCredentialByUsernameAndPassword(String username, String password, String scope) {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("grant_type", "password");
        parameters.put("username", username);
        parameters.put("password", password);
        if (StringUtils.isNotBlank(scope)) {
            parameters.put("scope", scope);
        }

        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes()));

        try {
            Request request = getTokenRequest(parameters, headers);
            try (Response response = httpClient.newCall(request).execute()) {
                String responseBody = response.body().string();
                if (response.isSuccessful()) {
                    Map<String, Object> resultMap = OBJECTMAPPER.readValue(responseBody, new TypeReference<HashMap<String, Object>>() {});

                    return new OAuth2Credential(this.providerName, (String) resultMap.get("access_token"), (String) resultMap.get("refresh_token"), null, null, (Integer) resultMap.get("expires_in"), null);
                } else {
                    throw new ContextedRuntimeException("get credential request failed!")
                            .addContextValue("requestUrl", request.url())
                            .addContextValue("requestHeaders", request.headers())
                            .addContextValue("requestBody", request.body())
                            .addContextValue("responseCode", response.code())
                            .addContextValue("responseBody", responseBody);
                }
            }

        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
    
    
    /**
     * Refresh access token using refresh token
     *
     * @param oldCredential The credential to refresh
     * @return The refreshed credential
     * @throws UnsupportedOperationException If the token endpoint type is not "QUERY" or "BODY", or if the credential has no refresh token.
     * @throws RuntimeException If the response is unsuccessful
     */
    public Optional<OAuth2Credential> refreshCredential(OAuth2Credential oldCredential) {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("client_id", this.clientId);
        parameters.put("client_secret", this.clientSecret);
        parameters.put("grant_type", "refresh_token");
        parameters.put("refresh_token", oldCredential.getRefreshToken());

        try {
            if (oldCredential.getRefreshToken() == null)
                throw new UnsupportedOperationException("Attempting to refresh a credential that has no refresh token.");

            Request request = getTokenRequest(parameters, Collections.emptyMap());
            try (Response response = httpClient.newCall(request).execute()) {
                String responseBody = response.body().string();
                if (response.isSuccessful()) {
                    Map<String, Object> resultMap = OBJECTMAPPER.readValue(responseBody, new TypeReference<HashMap<String, Object>>() {});

                    OAuth2Credential credential = new OAuth2Credential(this.providerName, (String) resultMap.get("access_token"), (String) resultMap.get("refresh_token"), null, null, (Integer) resultMap.get("expires_in"), null);
                    return Optional.of(credential);
                } else {
                    throw new RuntimeException("refreshCredential request failed! " + response.code() + ": " + responseBody);
                }
            }
        } catch (Exception ignored) {}

        return Optional.empty();
    }

    /**
     * Get a Credential for server-to-server requests using the OAuth2 Client Credentials Flow.
     *
     * @return The refreshed credential
     * @throws UnsupportedOperationException If the token endpoint type is not "QUERY" or "BODY"
     * @throws RuntimeException If the response is unsuccessful
     */
    public OAuth2Credential getAppAccessToken() {
        return getAppAccessToken(null);
    }

    /**
     * Get a Credential for server-to-server requests using the OAuth2 Client Credentials Flow.
     *
     * @param scope requested scopes
     * @return The refreshed credential
     * @throws UnsupportedOperationException If the token endpoint type is not "QUERY" or "BODY"
     * @throws RuntimeException If the response is unsuccessful
     */
    public OAuth2Credential getAppAccessToken(String scope) {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("client_id", this.clientId);
        parameters.put("client_secret", this.clientSecret);
        parameters.put("grant_type", "client_credentials");
        if (StringUtils.isNotBlank(scope)) {
            parameters.put("scope", scope);
        }

        try {
            Request request = getTokenRequest(parameters, Collections.emptyMap());
            try (Response response = httpClient.newCall(request).execute()) {
                String responseBody = response.body().string();
                if (response.isSuccessful()) {
                    Map<String, Object> resultMap = OBJECTMAPPER.readValue(responseBody, new TypeReference<HashMap<String, Object>>() {});

                    return new OAuth2Credential(this.providerName, (String) resultMap.get("access_token"), (String) resultMap.get("refresh_token"), null, null, (Integer) resultMap.get("expires_in"), null);
                } else {
                    throw new RuntimeException("getCredentialByClientCredentials request failed! " + response.code() + ": " + responseBody);
                }
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

    private Request getTokenRequest(Map<String, String> parameters, Map<String, String> headers) {
        Request request;

        switch (tokenEndpointPostType.toUpperCase()) {
            case "QUERY":
                HttpUrl.Builder urlBuilder = HttpUrl.parse(this.tokenUrl).newBuilder();
                parameters.forEach(urlBuilder::addQueryParameter);

                request = new Request.Builder()
                        .url(urlBuilder.build().toString())
                        .post(RequestBody.create(new byte[]{}, null))
                        .headers(Headers.of(headers))
                        .build();
                break;
            case "BODY":
                FormBody.Builder requestBody = new FormBody.Builder();
                parameters.forEach(requestBody::add);

                request = new Request.Builder()
                        .url(this.tokenUrl)
                        .post(requestBody.build())
                        .headers(Headers.of(headers))
                        .build();
                break;
            default:
                throw new UnsupportedOperationException("Unknown tokenEndpointPostType: " + tokenEndpointPostType);
        }

        return request;
    }

    @Override
    public boolean isValid(Credential credential) {
        if (credential instanceof OAuth2Credential) {
            OAuth2Credential oauthCred = (OAuth2Credential) credential;
            if (oauthCred.getReceivedAt() != null && oauthCred.getExpiresIn() != null) {
                return oauthCred.getReceivedAt().plusSeconds(oauthCred.getExpiresIn()).compareTo(Instant.now()) > 0;
            }
        }

        return false;
    }

    @Override
    public boolean renew(Credential credential) {
        if (credential instanceof OAuth2Credential) {
            OAuth2Credential oauthCred = (OAuth2Credential) credential;
            Optional<OAuth2Credential> updatedCredential = refreshCredential(oauthCred);
            if (updatedCredential.isPresent()) {
                oauthCred.updateCredential(updatedCredential.get());
                return true;
            }
        }

        return false;
    }
}
