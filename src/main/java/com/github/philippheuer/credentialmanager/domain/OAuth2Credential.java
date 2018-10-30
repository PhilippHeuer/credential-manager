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
     * @param userId           UserId
     * @param authToken        Authentication Token
     */
    public OAuth2Credential(String identityProvider, String userId, String authToken) {
        super(identityProvider, userId);
        this.authToken = authToken;
    }

    /**
     * Constructor
     *
     * @param identityProvider Identity Provider
     * @param userId           User Id
     * @param authToken        Authentication Token
     * @param userName         User Name
     * @param scopes           Scopes
     */
    public OAuth2Credential(String identityProvider, String userId, String authToken, String userName, List<String> scopes) {
        super(identityProvider, userId);
        this.authToken = authToken.startsWith("oauth:") ? authToken.replace("oauth:", "") : authToken;
        this.userName = userName;
        this.scopes = scopes;
    }

}
