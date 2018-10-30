package com.github.philippheuer.credentialmanager.identityprovider;

import com.github.philippheuer.credentialmanager.CredentialManager;
import com.github.philippheuer.credentialmanager.domain.IdentityProvider;
import com.github.philippheuer.credentialmanager.domain.OAuth2Credential;
import lombok.SneakyThrows;

import java.net.URLEncoder;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
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
    protected String responseType = "token";

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
        return URLEncoder.encode(String.format("%s?response_type=%s&client_id=%s&redirect_uri=%s&scope=%s&state=%s", authUrl, responseType, clientId, redirectUrl, String.join(scopeSeperator, scopes.stream().map(s -> s.toString()).collect(Collectors.toList())), state), "UTF-8");
    }

    /**
     * Get Token Information
     *
     * @param authToken Auth Token
     * @return Token Information
     */
    abstract public Optional<OAuth2Credential> getTokenInformation(String authToken);

    /**
     * Validate Token
     *
     * @param authToken Auth Token
     * @return true or false
     */
    abstract public Boolean validateToken(String authToken);

}
