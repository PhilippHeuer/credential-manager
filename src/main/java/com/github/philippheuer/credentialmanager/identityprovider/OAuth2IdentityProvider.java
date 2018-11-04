package com.github.philippheuer.credentialmanager.identityprovider;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.philippheuer.credentialmanager.domain.IdentityProvider;
import com.github.philippheuer.credentialmanager.domain.OAuth2Credential;
import lombok.SneakyThrows;
import okhttp3.*;

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
        this.clientId = clientId;
        this.clientSecret = clientSecret;
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

        try {
            HttpUrl.Builder urlBuilder = HttpUrl.parse(this.tokenUrl).newBuilder();
            urlBuilder.addQueryParameter("client_id", this.clientId);
            urlBuilder.addQueryParameter("client_secret", this.clientSecret);
            urlBuilder.addQueryParameter("code", code);
            urlBuilder.addQueryParameter("grant_type", "authorization_code");
            urlBuilder.addQueryParameter("redirect_uri", this.redirectUrl);

            Request request = new Request.Builder()
                    .url(urlBuilder.build().toString())
                    .post(RequestBody.create(null, new byte[]{}))
                    .build();

            Response response = client.newCall(request).execute();
            String responseBody = response.body().string();
            if (response.isSuccessful()) {
                Map<String, Object> resultMap = objectMapper.readValue(responseBody, new TypeReference<HashMap<String, Object>>() {});

                OAuth2Credential credential = new OAuth2Credential(this.providerName, (String) resultMap.get("access_token"), (String) resultMap.get("refresh_token"), null, null, (Integer) resultMap.get("expires_in"), null);
                return credential;
            } else {
                throw new RuntimeException("getCredentialByCode request failed! " + response.code() + ": " + responseBody);
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
