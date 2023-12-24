package com.github.philippheuer.credentialmanager.domain;

import java.util.Arrays;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Standardized possible error codes from
 * {@link com.github.philippheuer.credentialmanager.identityprovider.OAuth2IdentityProvider#getDeviceAccessToken(String)}.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8628#section-3.5">RFC 8628, Section 3.5</a>
 */
public enum DeviceFlowError {

    /**
     * The authorization request is still pending as the end user hasn't yet completed the user-interaction steps.
     */
    AUTHORIZATION_PENDING,

    /**
     * A variant of {@link #AUTHORIZATION_PENDING}, the authorization request is still pending and polling
     * should continue, but the interval MUST be increased by 5 seconds for this and all subsequent requests.
     */
    SLOW_DOWN,

    /**
     * The authorization request was denied.
     */
    ACCESS_DENIED,

    /**
     * The "device_code" has expired, and the device authorization session has concluded.
     * The client MAY commence a new device authorization request but SHOULD wait for
     * user interaction before restarting to avoid unnecessary polling.
     */
    EXPIRED_TOKEN,

    /**
     * The request is missing a required parameter, includes an unsupported parameter value (other than grant type),
     * repeats a parameter, includes multiple credentials, utilizes more than one mechanism
     * for authenticating the client, or is otherwise malformed.
     * <p>
     * This should not occur from {@link com.github.philippheuer.credentialmanager.identityprovider.OAuth2IdentityProvider}
     * unless the authorization server does not strictly follow the RFC.
     */
    INVALID_REQUEST,

    /**
     * Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).
     * <p>
     * This should not occur from {@link com.github.philippheuer.credentialmanager.authcontroller.DeviceFlowController}.
     */
    INVALID_CLIENT,

    /**
     * The provided authorization grant is invalid, expired, revoked, or was issued to another client.
     */
    INVALID_GRANT,

    /**
     * The authenticated client is not authorized to use this authorization grant type.
     */
    UNAUTHORIZED_CLIENT,

    /**
     * The authorization grant type is not supported by the authorization server.
     */
    UNSUPPORTED_GRANT_TYPE,

    /**
     * The auth server sent an error that is not standardized in the
     * Device Authorization Grant RFC or OAuth 2.0 Authorization Framework RFC.
     */
    UNKNOWN;

    private static final Map<String, DeviceFlowError> MAPPINGS = Arrays.stream(values())
            .collect(Collectors.toMap(Enum::toString, Function.identity()));

    /**
     * Whether to keep retrying the access token request.
     */
    public boolean shouldRetry() {
        return this == AUTHORIZATION_PENDING || this == SLOW_DOWN;
    }

    @Override
    public String toString() {
        return this.name().toLowerCase();
    }

    /**
     * @param code The error code as a lowercase string (as defined by the RFC)
     * @return {@link DeviceFlowError}
     */
    public static DeviceFlowError from(String code) {
        return MAPPINGS.getOrDefault(code, UNKNOWN);
    }
}
