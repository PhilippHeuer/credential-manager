package com.github.philippheuer.credentialmanager.domain;

import lombok.*;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
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
    }

    /**
     * Constructor
     *
     * @param identityProvider Identity Provider
     * @param accessToken      Authentication Token
     * @param context          Credential context
     */
    public OAuth2Credential(String identityProvider, String accessToken, @NotNull Map<String, Object> context) {
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
        this.scopes = scopes != null ? scopes : new ArrayList<>(0);
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
        this.scopes = scopes != null ? scopes : new ArrayList<>(0);
        this.context = context != null ? context : new HashMap<>(0);
    }

    /**
     * Updates the values with the input from the provided new credential
     *
     * @param newCredential the OAuth2Credential with additional information
     */
    public void updateCredential(OAuth2Credential newCredential) {
        if (newCredential.accessToken != null) {
            this.accessToken = newCredential.accessToken;
        }
        if (newCredential.refreshToken != null) {
            this.refreshToken = newCredential.refreshToken;
        }
        if (newCredential.expiresIn != null) {
            this.expiresIn = newCredential.expiresIn;
        }
        if (newCredential.userId != null) {
            this.userId = newCredential.userId;
        }
        if (newCredential.userName != null) {
            this.userName = newCredential.userName;
        }
        if (newCredential.scopes != null && !newCredential.scopes.isEmpty()) {
            this.scopes.clear();
            this.scopes.addAll(newCredential.scopes);
        }
        if (newCredential.context != null && !newCredential.context.isEmpty()) {
            this.context.clear();
            this.context.putAll(newCredential.context);
        }
    }

}
