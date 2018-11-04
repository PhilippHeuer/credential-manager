package com.github.philippheuer.credentialmanager.authcontroller;

import com.github.philippheuer.credentialmanager.domain.AuthenticationController;
import com.github.philippheuer.credentialmanager.identityprovider.OAuth2IdentityProvider;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

/**
 * Dummy Authentication Controller
 */
@Slf4j
public class DummyAuthController extends AuthenticationController {

    /**
     * Constructor
     */
    public DummyAuthController() {
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
    public void startOAuth2AuthorizationCodeGrantType(OAuth2IdentityProvider oAuth2IdentityProvider, String redirectUrl, List<Object> scopes) {
        log.debug("Called startOAuth2ImplicitGrantType!");
    }

}
