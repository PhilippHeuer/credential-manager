package com.github.philippheuer.credentialmanager.domain;

import lombok.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * OAuth Credential
 */
@Getter
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
public class OAuth2Credential extends Credential {

    /**
     * Access Token
     */
    @Setter
    private String accessToken;

    /**
     * Refresh Token
     */
    @Setter
    private String refreshToken;

    /**
     * User Name
     */
    private String userName;

    /**
     * Token Expiry (in seconds, if complaint with RFC 6749)
     */
    @Setter
    private Integer expiresIn;

    /**
     * OAuth Scopes
     */
    private List<String> scopes;

    /**
     * Access Token context that can be used to store additional information
     */
    private Map<String, Object> context;

    /**
     * Constructor
     *
     * @param identityProvider Identity Provider
     * @param accessToken      Authentication Token
     */
    public OAuth2Credential(String identityProvider, String accessToken) {
        this(identityProvider, accessToken, null, null, null, null, null);
        this.context = new HashMap<>();
    }

    /**
     * Constructor
     *
     * @param identityProvider Identity Provider
     * @param accessToken      Authentication Token
     * @param context          Credential context
     */
    public OAuth2Credential(String identityProvider, String accessToken, Map<String, Object> context) {
        this(identityProvider, accessToken, null, null, null, null, null);
        this.context = context;
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
        this.expiresIn = expiresIn;
        this.scopes = scopes;
        this.context = new HashMap<>();
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
     * @param context          Credential context
     */
    public OAuth2Credential(String identityProvider, String accessToken, String refreshToken, String userId, String userName, Integer expiresIn, List<String> scopes, Map<String, Object> context) {
        super(identityProvider, userId);
        this.accessToken = accessToken.startsWith("oauth:") ? accessToken.replace("oauth:", "") : accessToken;
        this.refreshToken = refreshToken;
        this.userName = userName;
        this.expiresIn = expiresIn;
        this.scopes = scopes;
        this.context = context;
    }

}
