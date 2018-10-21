package com.github.philippheuer.credentialmanager.domain;

import lombok.Getter;
import lombok.ToString;

import java.util.List;

/**
 * OAuth Credential
 */
@Getter
@ToString
public class OAuth2Credential extends Credential {

    /**
     * Auth Token
     */
    private final String authToken;

    /**
     * User Id
     */
    private String userId;

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
     * @param authToken        Authentication Token
     */
    public OAuth2Credential(String identityProvider, String authToken) {
        super(identityProvider);
        this.authToken = authToken;
    }

    /**
     * Constructor
     *
     * @param identityProvider Identity Provider
     * @param authToken        Authentication Token
     * @param userId           User Id
     * @param userName         User Name
     * @param scopes           Scopes
     */
    public OAuth2Credential(String identityProvider, String authToken, String userId, String userName, List<String> scopes) {
        super(identityProvider);
        this.authToken = authToken;
        this.userId = userId;
        this.userName = userName;
        this.scopes = scopes;
    }

}
