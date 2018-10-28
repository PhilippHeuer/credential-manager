package com.github.philippheuer.credentialmanager.identityprovider;

import com.github.philippheuer.credentialmanager.domain.IdentityProvider;
import com.github.philippheuer.credentialmanager.domain.OAuth2Credential;

import java.util.List;
import java.util.Optional;

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
     * Constructor
     *
     * @param providerName Provider Name
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
     * @return url
     */
    public String getAuthenticationUrl(List<String> scopes) {
        return getAuthenticationUrl(this.redirectUrl, scopes);
    }

    /**
     * Get Authentication Url
     *
     * @param redirectUrl overwrite the redirect url with a custom one
     * @param scopes      requested scopes
     * @return url
     */
    public String getAuthenticationUrl(String redirectUrl, List<String> scopes) {
        return String.format("%s?response_type=token&client_id=%s&redirect_uri=%s&scope=%s", authUrl, clientId, redirectUrl, String.join(scopeSeperator, scopes));
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
