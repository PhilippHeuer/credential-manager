package com.github.philippheuer.credentialmanager.identityprovider;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import com.github.philippheuer.credentialmanager.domain.Credential;
import com.github.philippheuer.credentialmanager.domain.DeviceAuthorization;
import com.github.philippheuer.credentialmanager.domain.DeviceFlowError;
import com.github.philippheuer.credentialmanager.domain.DeviceTokenResponse;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
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
     * Device Flow Endpoint
     */
    protected String deviceUrl;

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
        this(providerName, providerType, clientId, clientSecret, authUrl, tokenUrl, null, redirectUrl, ProxyHelper.selectProxy());
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
     * @param proxy        HTTP Proxy
     * @deprecated in favor of {@link OAuth2IdentityProvider#OAuth2IdentityProvider(String, String, String, String, String, String, String, String, Proxy)}
     */
    @Deprecated
    public OAuth2IdentityProvider(String providerName, String providerType, String clientId, String clientSecret, String authUrl, String tokenUrl, String redirectUrl, Proxy proxy) {
        this(providerName, providerType, clientId, clientSecret, authUrl, tokenUrl, null, redirectUrl, proxy);
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
     * @param deviceUrl    Device Flow URL
     * @param redirectUrl  Redirect URL
     * @param proxy        HTTP Proxy
     */
    public OAuth2IdentityProvider(String providerName, String providerType, String clientId, String clientSecret, String authUrl, String tokenUrl, String deviceUrl, String redirectUrl, Proxy proxy) {
        this.providerName = providerName;
        this.providerType = providerType;
        this.clientId = clientId == null ? "" : clientId;
        this.clientSecret = clientSecret == null ? "" : clientSecret;
        this.authUrl = authUrl;
        this.tokenUrl = tokenUrl;
        this.deviceUrl = deviceUrl;
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
     * Begins the Device Authorization Grant Flow by requesting verification codes from the auth server.
     * <p>
     * Once this request has been created, one can repeatedly poll {@link #getDeviceAccessToken(String)}
     * with {@link DeviceAuthorization#getDeviceCode()} to try to complete the device flow.
     * This process can be automated by utilizing {@link com.github.philippheuer.credentialmanager.authcontroller.DeviceFlowController}.
     *
     * @param scopes Requested scopes
     * @return object with the verification uri and code for the user to input in their browser.
     * @throws RuntimeException if the request could not be executed, caused by an {@link java.io.IOException}.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8628#section-3.1">RFC 8628, Section 3.1 and 3.2</a>
     */
    public DeviceAuthorization createDeviceFlowRequest(Collection<Object> scopes) {
        FormBody.Builder requestBody = new FormBody.Builder();
        requestBody.add("client_id", this.clientId);
        if (scopes != null && !scopes.isEmpty()) {
            requestBody.add("scope",
                    scopes.stream().map(Object::toString).collect(Collectors.joining(" ")));
        }
        Request request = new Request.Builder()
                .url(this.deviceUrl)
                .post(requestBody.build())
                .build();
        try (Response response = httpClient.newCall(request).execute()) {
            String responseBody = response.body() != null ? response.body().string() : null;
            if (response.isSuccessful()) {
                return OBJECTMAPPER.readValue(responseBody, DeviceAuthorization.class);
            } else {
                throw new ContextedRuntimeException("createDeviceFlowRequest failed!")
                        .addContextValue("requestUrl", request.url())
                        .addContextValue("requestBody", request.body())
                        .addContextValue("responseCode", response.code())
                        .addContextValue("responseBody", responseBody);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Exchanges the {@code device_code} for a device token if the user has authorized your application.
     * <p>
     * This method should be repeatedly polled, depending on the returned error code,
     * until the token is available or the user has cancelled the flow in your application.
     * This process can be automated by utilizing {@link com.github.philippheuer.credentialmanager.authcontroller.DeviceFlowController}.
     *
     * @param deviceCode {@link DeviceAuthorization#getDeviceCode()} from {@link #createDeviceFlowRequest(Collection)}
     * @return {@link DeviceTokenResponse}, which contains a {@link OAuth2Credential} or {@link DeviceFlowError}.
     * @throws ContextedRuntimeException if the request did not succeed and the response body does not adhere to RFC format.
     * @throws RuntimeException if the request could not be executed (caused by an {@link java.io.IOException}) or
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8628#section-3.4">RFC 8628, Section 3.4 and 3.5</a>
     */
    public DeviceTokenResponse getDeviceAccessToken(String deviceCode) {
        FormBody requestBody = new FormBody.Builder()
                .add("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
                .add("device_code", deviceCode)
                .add("client_id", this.clientId)
                .build();
        Request request = new Request.Builder()
                .url(this.tokenUrl)
                .post(requestBody)
                .build();
        try (Response response = httpClient.newCall(request).execute()) {
            JsonNode body = response.body() != null ? OBJECTMAPPER.readTree(response.body().charStream()) : null;
            if (response.isSuccessful() && body != null) {
                JsonNode expiry = body.get("expires_in");
                JsonNode scope = body.get("scope");
                List<String> scopes = new ArrayList<>(0);
                if (scope != null) {
                    if (scope.isTextual()) {
                        // Auth server follows the RFC
                        scopes.addAll(Arrays.asList(scope.textValue().split(" ")));
                    } else if (scope.isArray()) {
                        // Not within the RFC spec, like Twitch's implementation
                        scope.elements().forEachRemaining(node -> {
                            if (node.isTextual()) {
                                scopes.add(node.textValue());
                            }
                        });
                    }
                }
                OAuth2Credential credential = new OAuth2Credential(this.providerName, body.get("access_token").textValue(), body.get("refresh_token").textValue(), null, null, expiry.isInt() ? expiry.intValue() : null, scopes);
                credential.getContext().put("client_id", clientId);
                return new DeviceTokenResponse(credential, null);
            } else {
                // RFC labels this field as `error`, but non-standard implementations (like Twitch) may use `message`
                JsonNode errorNode = body == null ? null : body.has("error") ? body.get("error") : body.get("message");
                if (errorNode == null || !errorNode.isTextual()) {
                    // unexpected response format; throw exception
                    throw new ContextedRuntimeException("getCredentialByCode request failed!")
                            .addContextValue("requestUrl", request.url())
                            .addContextValue("requestHeaders", request.headers())
                            .addContextValue("requestBody", request.body())
                            .addContextValue("responseCode", response.code())
                            .addContextValue("responseBody", body);
                }
                DeviceFlowError error = DeviceFlowError.from(errorNode.textValue());
                return new DeviceTokenResponse(null, error);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
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
        parameters.put("grant_type", "refresh_token");
        parameters.put("refresh_token", oldCredential.getRefreshToken());
        if (clientSecret != null) {
            // not required for device flow
            parameters.put("client_secret", this.clientSecret);
        }

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
            if (oauthCred.getIssuedAt() != null && oauthCred.getExpiresIn() != null) {
                return oauthCred.getIssuedAt().plusSeconds(oauthCred.getExpiresIn()).compareTo(Instant.now()) > 0;
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
