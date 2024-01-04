package com.github.philippheuer.credentialmanager.authcontroller;

import com.github.philippheuer.credentialmanager.CredentialManager;
import com.github.philippheuer.credentialmanager.domain.AuthenticationController;
import com.github.philippheuer.credentialmanager.domain.DeviceAuthorization;
import com.github.philippheuer.credentialmanager.domain.DeviceFlowError;
import com.github.philippheuer.credentialmanager.domain.DeviceTokenResponse;
import com.github.philippheuer.credentialmanager.domain.OAuth2Credential;
import com.github.philippheuer.credentialmanager.identityprovider.OAuth2IdentityProvider;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.compare.ComparableUtils;
import org.jetbrains.annotations.Nullable;

import java.io.Closeable;
import java.io.IOException;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Facilitates the Device Authorization Grant Flow; repeatedly checks if the device token is available.
 */
@Slf4j
public final class DeviceFlowController extends AuthenticationController implements Closeable {

    private final int maxExpiresIn;
    private final ScheduledExecutorService executor;
    private final boolean shouldCloseExecutor;
    private volatile boolean closed = false;

    /**
     * Creates a {@link DeviceFlowController} with default settings.
     */
    public DeviceFlowController() {
        this(null, 0);
    }

    /**
     * Creates a {@link DeviceFlowController} with the specified executor and maximum expiry seconds.
     *
     * @param executor     an optional {@link ScheduledExecutorService}
     * @param maxExpiresIn the maximum duration in seconds to repeatedly request a device token; ignored if not positive
     */
    public DeviceFlowController(@Nullable ScheduledExecutorService executor, int maxExpiresIn) {
        this.maxExpiresIn = maxExpiresIn;
        if (executor != null) {
            this.executor = executor;
            this.shouldCloseExecutor = false;
        } else {
            this.executor = Executors.newSingleThreadScheduledExecutor();
            this.shouldCloseExecutor = true;
        }
    }

    @Override
    public DeviceAuthorization startOAuth2DeviceAuthorizationGrantType(OAuth2IdentityProvider oAuth2IdentityProvider, Collection<Object> scopes, Consumer<DeviceTokenResponse> callback) {
        DeviceAuthorization request = oAuth2IdentityProvider.createDeviceFlowRequest(scopes);
        AtomicInteger interval = new AtomicInteger(request.getInterval());
        Instant expiry = maxExpiresIn > 0
                ? ComparableUtils.min(request.getIssuedAt().plusSeconds(maxExpiresIn), request.getExpiresAt())
                : request.getExpiresAt();
        schedule(oAuth2IdentityProvider, request.getDeviceCode(), request.getUserCode(), expiry, interval, callback);
        return request;
    }

    @Override
    public void startOAuth2AuthorizationCodeGrantType(OAuth2IdentityProvider oAuth2IdentityProvider, String redirectUrl, List<Object> scopes) {
        throw new UnsupportedOperationException("This controller only facilitates the Device Authorization Grant Flow.");
    }

    @Override
    public void close() {
        this.closed = true;
        if (this.shouldCloseExecutor) {
            this.executor.shutdownNow();
        }
    }

    private void schedule(OAuth2IdentityProvider identityProvider, String deviceCode, String userCode, Instant expiry, AtomicInteger interval, Consumer<DeviceTokenResponse> callback) {
        executor.schedule(() -> {
            if (this.closed) {
                log.info("Cancelling device code flow for user {} since controller was closed", userCode);
                callback.accept(null);
                return;
            }

            if (Instant.now().isAfter(expiry)) {
                callback.accept(new DeviceTokenResponse(null, DeviceFlowError.EXPIRED_TOKEN));
                return;
            }

            DeviceTokenResponse response;
            try {
                response = identityProvider.getDeviceAccessToken(deviceCode);
            } catch (Exception e) {
                response = null;
                log.warn("Encountered exception when checking for device access token; will retry...", e);

                if (e.getCause() instanceof IOException) {
                    // On encountering a connection timeout, clients MUST unilaterally reduce their polling
                    // frequency before retrying. The use of an exponential backoff algorithm to achieve this,
                    // such as doubling the polling interval on each such connection timeout, is RECOMMENDED.
                    // https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
                    interval.updateAndGet(i -> i <= 30 ? i * 2 : i + 10);
                }
            }

            if (response != null) {
                OAuth2Credential credential = response.getCredential();
                assert credential != null || response.getError() != null;
                if (credential != null || !response.getError().shouldRetry()) {
                    CredentialManager credentialManager = getCredentialManager();
                    if (credential != null && credentialManager != null) {
                        credentialManager.addCredential(identityProvider.getProviderName(), credential);
                    }

                    callback.accept(response);
                    return;
                } else {
                    log.debug("Received {} error from device token endpoint for user {}; will retry...", response.getError(), userCode);
                    if (response.getError() == DeviceFlowError.SLOW_DOWN) {
                        interval.addAndGet(5);
                    }
                }
            }

            // try again later
            this.schedule(identityProvider, deviceCode, userCode, expiry, interval, callback);
        }, interval.get(), TimeUnit.SECONDS);
    }
}
