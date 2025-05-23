package com.github.philippheuer.credentialmanager.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.jetbrains.annotations.NotNull;

import java.time.Instant;
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
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
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
     * Token Issued Timestamp
     */
    @Setter
    @JsonFormat(shape = JsonFormat.Shape.STRING, timezone = "UTC")
    private Instant issuedAt;

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
        this(identityProvider, accessToken, null, null, null, null, null, context);
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
        this(identityProvider, accessToken, refreshToken, userId, userName, expiresIn, scopes, null);
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
        this(identityProvider, accessToken, refreshToken, userId, userName, null, expiresIn, scopes, context);
    }

    /**
     * Constructor
     *
     * @param identityProvider Identity Provider
     * @param accessToken      Authentication Token
     * @param refreshToken     Refresh Token
     * @param userId           User Id
     * @param userName         User Name
     * @param issuedAt         Timestamp of when the token was issued
     * @param expiresIn        Expires in x seconds
     * @param scopes           Scopes
     * @param context          Credential context
     */
    @JsonCreator
    public OAuth2Credential(
            @JsonProperty("identity_provider") String identityProvider,
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("refresh_token") String refreshToken,
            @JsonProperty("user_id") String userId,
            @JsonProperty("user_name") String userName,
            @JsonProperty("issued_at") Instant issuedAt,
            @JsonProperty("expires_in") Integer expiresIn,
            @JsonProperty("scopes") List<String> scopes,
            @JsonProperty("context") Map<String, Object> context
    ) {
        super(identityProvider, userId);
        this.accessToken = accessToken.startsWith("oauth:") ? accessToken.substring("oauth:".length()) : accessToken;
        this.refreshToken = refreshToken;
        this.userName = userName;
        this.issuedAt = issuedAt != null ? issuedAt : Instant.now();
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
        if (newCredential.issuedAt != null) {
            this.issuedAt = newCredential.issuedAt;
        }
    }

    /**
     * @return the time at which the token was created
     * @deprecated in favor of {@link #getIssuedAt()}
     */
    @Deprecated
    @JsonIgnore
    public Instant getReceivedAt() {
        return issuedAt;
    }

    /**
     * @param receivedAt the time at which the token was created
     * @deprecated in favor of {@link #setIssuedAt(Instant)}
     */
    @Deprecated
    @JsonIgnore
    public void setReceivedAt(Instant receivedAt) {
        this.issuedAt = receivedAt;
    }

    /**
     * Calculates the approximate timestamp when this token will no longer be valid.
     *
     * <ul>
     *   <li>If {@code issuedAt} is {@code null}, the token is considered expired - {@code Instant.MIN}.</li>
     *   <li>If {@code expiresIn} is {@code null}, the token is considered to never expire - {@code Instant.MAX}.</li>
     * </ul>
     *
     * @return Instant when the token expires
     */
    @JsonIgnore
    public Instant getExpiresAt() {
        if (issuedAt == null) return Instant.MIN; // missing issuedAt timestamp
        if (expiresIn == null) return Instant.MAX; // no expiration
        return issuedAt.plusSeconds(this.expiresIn);
    }

    /**
     * Checks whether the token has expired.
     *
     * <ul>
     *   <li>If {@code issuedAt} is {@code null}, the token is considered expired.</li>
     *   <li>If {@code expiresIn} is {@code null}, the token is considered to never expire.</li>
     *   <li>Otherwise, the token is considered expired, if the current time is after
     *       {@code issuedAt + expiresIn} seconds.</li>
     * </ul>
     *
     * @return {@code true} if the token has expired, {@code false} otherwise
     */
    @JsonIgnore
    public boolean isExpired() {
        return Instant.now().isAfter(getExpiresAt());
    }
}
