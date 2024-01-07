package com.github.philippheuer.credentialmanager.domain;

import lombok.Value;
import org.jetbrains.annotations.Nullable;

/**
 * Device Access Token Response, yielded by
 * {@link com.github.philippheuer.credentialmanager.identityprovider.OAuth2IdentityProvider#getDeviceAccessToken(String)}.
 * <p>
 * If the user has approved the grant, {@link #getCredential()} will be populated.
 * Otherwise, {@link #getError()} will be present.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8628#section-3.5">RFC 8628, Section 3.5</a>
 */
@Value
public class DeviceTokenResponse {

    /**
     * The device token, given the user has approved the grant.
     */
    @Nullable
    OAuth2Credential credential;

    /**
     * A potentially-retryable error when attempting to obtain the device token.
     */
    @Nullable
    DeviceFlowError error;

}
