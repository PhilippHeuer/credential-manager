package com.github.philippheuer.credentialmanager;

import com.github.philippheuer.credentialmanager.api.IStorageBackend;
import com.github.philippheuer.credentialmanager.authcontroller.DummyAuthController;
import com.github.philippheuer.credentialmanager.domain.AuthenticationController;
import com.github.philippheuer.credentialmanager.domain.IdentityProvider;
import com.github.philippheuer.credentialmanager.storage.TemporaryStorageBackend;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.With;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Credential Manager Builder
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class CredentialManagerBuilder {

    /**
     * Storage Backend
     */
    @With
    private IStorageBackend storageBackend = new TemporaryStorageBackend();

    /**
     * Authentication Controller
     */
    @With
    private AuthenticationController authenticationController = new DummyAuthController();

    /**
     * Initial Identity Providers
     */
    @With
    private Collection<IdentityProvider> identityProviders = new ArrayList<>();

    /**
     * Initialize the builder
     *
     * @return CredentialManager Builder
     */
    public static CredentialManagerBuilder builder() {
        return new CredentialManagerBuilder();
    }

    /**
     * CredentialManager
     *
     * @return CredentialManager
     */
    public CredentialManager build() {
        CredentialManager credentialManager = new CredentialManager(this.storageBackend, this.authenticationController, this.identityProviders);
        return credentialManager;
    }

    /**
     * Adds an identity provider to be registered with the {@link CredentialManager}.
     *
     * @param identityProvider the identity provider to register on manager construction
     * @return a new {@link CredentialManagerBuilder}
     */
    public CredentialManagerBuilder withIdentityProvider(@NotNull IdentityProvider identityProvider) {
        List<IdentityProvider> providers = new ArrayList<>(identityProviders);
        providers.add(identityProvider);
        return this.withIdentityProviders(providers);
    }
}
