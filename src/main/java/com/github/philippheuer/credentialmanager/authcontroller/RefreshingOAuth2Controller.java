package com.github.philippheuer.credentialmanager.authcontroller;

import com.github.philippheuer.credentialmanager.CredentialManager;
import com.github.philippheuer.credentialmanager.domain.AuthenticationController;
import com.github.philippheuer.credentialmanager.domain.Credential;
import com.github.philippheuer.credentialmanager.domain.DeviceAuthorization;
import com.github.philippheuer.credentialmanager.domain.DeviceTokenResponse;
import com.github.philippheuer.credentialmanager.domain.OAuth2Credential;
import com.github.philippheuer.credentialmanager.identityprovider.OAuth2IdentityProvider;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Decorates another {@link AuthenticationController} to add automatic refreshing support.
 * <p>
 * Be sure to register a persistent {@link com.github.philippheuer.credentialmanager.api.IStorageBackend}
 * when constructing the {@link CredentialManager}.
 */
@Slf4j
public class RefreshingOAuth2Controller extends AuthenticationController {

    private static final Duration DEFAULT_MIN_INTERVAL = Duration.ofHours(1L);

    private final AuthenticationController delegate;
    private final ScheduledExecutorService executor;
    private final long minimumRefreshInterval;

    public RefreshingOAuth2Controller(AuthenticationController delegate, ScheduledExecutorService executor, Duration minimumRefreshInterval) {
        this.delegate = delegate;
        this.executor = executor;
        this.minimumRefreshInterval = minimumRefreshInterval.getSeconds();
    }

    public RefreshingOAuth2Controller(AuthenticationController delegate, ScheduledExecutorService executor) {
        this(delegate, executor, DEFAULT_MIN_INTERVAL);
    }

    public RefreshingOAuth2Controller(ScheduledExecutorService executor) {
        this(new DummyAuthController(), executor);
    }

    public RefreshingOAuth2Controller() {
        this(Executors.newSingleThreadScheduledExecutor());
    }

    @Override
    public void startOAuth2AuthorizationCodeGrantType(OAuth2IdentityProvider oAuth2IdentityProvider, String redirectUrl, List<Object> scopes) {
        delegate.startOAuth2AuthorizationCodeGrantType(oAuth2IdentityProvider, redirectUrl, scopes);
    }

    @Override
    public DeviceAuthorization startOAuth2DeviceAuthorizationGrantType(OAuth2IdentityProvider oAuth2IdentityProvider, Collection<Object> scopes, Consumer<DeviceTokenResponse> callback) {
        return delegate.startOAuth2DeviceAuthorizationGrantType(oAuth2IdentityProvider, scopes, callback);
    }

    @Override
    public CredentialManager getCredentialManager() {
        return delegate.getCredentialManager();
    }

    @Override
    public void setCredentialManager(CredentialManager credentialManager) {
        delegate.setCredentialManager(credentialManager);
    }

    @Override
    public void registerCredential(Credential credential) {
        delegate.registerCredential(credential);

        if (credential instanceof OAuth2Credential) {
            OAuth2Credential cred = (OAuth2Credential) credential;
            if (cred.getExpiresIn() != null) {
                initializeCredential(cred);
            } else {
                executor.execute(() -> {
                    OAuth2IdentityProvider ip = getIdentityProvider(cred);
                    boolean valid = ip.getAdditionalCredentialInformation(cred)
                            .map(enriched -> {
                                cred.updateCredential(enriched);
                                return true;
                            })
                            .orElseGet(() -> tryRefresh(ip, cred));
                    if (valid) {
                        initializeCredential(cred);
                    }
                });
            }
        }
    }

    private void initializeCredential(OAuth2Credential credential) {
        Integer expiresIn = credential.getExpiresIn();
        if (expiresIn == null || expiresIn <= 0) return;

        long expiry = Math.max(Duration.between(Instant.now(), credential.getIssuedAt().plusSeconds(expiresIn)).getSeconds(), 0L);
        long initialDelay = expiry * 3L / 4L;
        long interval = Math.max(minimumRefreshInterval, expiry);
        executor.scheduleAtFixedRate(() -> tryRefresh(getIdentityProvider(credential), credential), initialDelay, interval, TimeUnit.SECONDS);
    }

    private boolean tryRefresh(OAuth2IdentityProvider identityProvider, OAuth2Credential credential) {
        if (StringUtils.isNotEmpty(credential.getRefreshToken())) {
            // user token
            Optional<OAuth2Credential> refreshed = identityProvider.refreshCredential(credential);
            if (refreshed.isPresent()) {
                credential.updateCredential(refreshed.get());
                return true;
            } else {
                log.warn("Could not refresh credential; it may be revoked! {}", credential);
            }
        } else if (StringUtils.isEmpty(credential.getUserId())) {
            // app access token
            credential.updateCredential(identityProvider.getAppAccessToken(String.join(" ", credential.getScopes())));
            return true;
        } else {
            log.trace("Credential for User ID {} does not have sufficient information to be able to be refreshed", credential.getUserId());
        }
        return false;
    }

    private OAuth2IdentityProvider getIdentityProvider(OAuth2Credential credential) {
        return getCredentialManager().getOAuth2IdentityProviderByName(credential.getIdentityProvider())
                .orElseThrow(() -> new RuntimeException("OAuth2Credential is missing corresponding identity provider"));
    }
}
