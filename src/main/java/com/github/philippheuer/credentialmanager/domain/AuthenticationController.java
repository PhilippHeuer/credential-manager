package com.github.philippheuer.credentialmanager.domain;

import com.github.philippheuer.credentialmanager.CredentialManager;
import com.github.philippheuer.credentialmanager.identityprovider.OAuth2IdentityProvider;
import lombok.Getter;
import lombok.Setter;

import java.util.Collection;
import java.util.List;
import java.util.function.Consumer;

public abstract class AuthenticationController {

    /**
     * Holds the CredentialManager
     */
    @Setter
    @Getter
    CredentialManager credentialManager;

    /**
     * Constructor
     */
    public AuthenticationController() {
        // nothing
    }

    /**
     * Starts the OAuth2Flow for the specified OAuth2 Identity Provider
     * <p>
     * It starts out by building a link and directing the user’s browser to that URL. At a high level, the flow has the following steps
     * The application opens a browser to send the user to the OAuth server
     * The user sees the authorization prompt and approves the app’s request
     * The user is redirected back to the application with an code in the URL fragment
     * The server uses the code to retrieve a access token
     *
     * @param oAuth2IdentityProvider OAuth2 Identity Provider
     * @param redirectUrl            Redirect url
     * @param scopes                 Requested scopes
     */
    public abstract void startOAuth2AuthorizationCodeGrantType(OAuth2IdentityProvider oAuth2IdentityProvider, String redirectUrl, List<Object> scopes);

    /**
     * Starts the Device Authorization Grant Flow for the specified OAuth2 Identity Provider
     * <p>
     * This protocol only requires a one-way channel in order to maximize the viability of the protocol
     * in restricted environments, like an application running on a TV that is only capable of outbound requests.
     * <p>
     * It starts by requesting a verification link from the authorization server that should be presented to the user.
     * The user navigates to the page, inserts the {@link DeviceAuthorization#getUserCode()}, and authorizes the app.
     * Finally, the {@code callback} will be invoked with the authorized device token (in an ideal scenario).
     *
     * @param oAuth2IdentityProvider OAuth2 Identity Provider
     * @param scopes                 Requested scopes
     * @param callback               Consumes the final {@link DeviceTokenResponse}, containing a credential or un-retryable error
     * @return {@link DeviceAuthorization} so the completed verification uri can be presented to the end user
     */
    public DeviceAuthorization startOAuth2DeviceAuthorizationGrantType(OAuth2IdentityProvider oAuth2IdentityProvider, Collection<Object> scopes, Consumer<DeviceTokenResponse> callback) {
        // default method body to avoid a breaking change
        throw new UnsupportedOperationException("This controller does not implement the Device Authorization Grant Flow.");
    }

}
