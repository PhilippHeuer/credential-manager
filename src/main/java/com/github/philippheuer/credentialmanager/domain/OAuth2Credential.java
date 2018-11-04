package com.github.philippheuer.credentialmanager.domain;

import lombok.Getter;
import lombok.ToString;

import java.util.List;

/**
 * OAuth Credential
 */
@Getter
@ToString(callSuper = true)
public class OAuth2Credential extends Credential {

    /**
     * Access Token
     */
    private String accessToken;

    /**
     * Refresh Token
     */
    private String refreshToken;

    /**
     * User Name
     */
    private String userName;

    /**
     * OAuth Scopes
     */
    private List<String> scopes;

    /**
     * Constructor
     *
     * @param identityProvider Identity Provider
     * @param accessToken      Authentication Token
     */
    public OAuth2Credential(String identityProvider, String accessToken) {
        this(identityProvider, accessToken, null, null, null, null, null);
    }

    /**
     * Constructor
     *
     * @param identityProvider Identity Provider
     * @param accessToken      Authentication Token
     * @param refreshToken     Refresh Token
     * @param userId           User Id
     * @param userName         User Name
     * @param expiresIn        Expires in x seconds
     * @param scopes           Scopes
     */
    public OAuth2Credential(String identityProvider, String accessToken, String refreshToken, String userId, String userName, Integer expiresIn, List<String> scopes) {
        super(identityProvider, userId);
        this.accessToken = accessToken.startsWith("oauth:") ? accessToken.replace("oauth:", "") : accessToken;
        this.refreshToken = refreshToken;
        this.userName = userName;
        this.scopes = scopes;
    }

}
