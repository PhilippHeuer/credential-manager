package com.github.philippheuer.credentialmanager.identityprovider;

import com.github.philippheuer.credentialmanager.domain.OAuth2Credential;

import java.util.Optional;

public class DefaultOAuth2IdentityProvider extends OAuth2IdentityProvider {

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
     * @param tokenEndpointPostType Token Endpoint Post Type
     */
    public DefaultOAuth2IdentityProvider(String providerName, String providerType, String clientId, String clientSecret, String authUrl, String tokenUrl, String redirectUrl, String tokenEndpointPostType) {
        super(providerName, providerType, clientId, clientSecret, authUrl, tokenUrl, redirectUrl);

        this.tokenEndpointPostType = tokenEndpointPostType != null ? tokenEndpointPostType : this.tokenEndpointPostType;
    }

    /**
     * Get Token Information
     *
     * @param credential OAuth2 Credential
     * @return Token Information
     */
    public Optional<OAuth2Credential> getAdditionalCredentialInformation(OAuth2Credential credential) {
        return Optional.empty();
    }

}
