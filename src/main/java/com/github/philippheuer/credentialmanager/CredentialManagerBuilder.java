package com.github.philippheuer.credentialmanager;

import com.github.philippheuer.credentialmanager.api.IAuthenticationController;
import com.github.philippheuer.credentialmanager.api.IStorageBackend;
import com.github.philippheuer.credentialmanager.authcontroller.DummyAuthController;
import com.github.philippheuer.credentialmanager.storage.TemporaryStorageBackend;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.experimental.Wither;
import lombok.extern.slf4j.Slf4j;

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
    @Wither
    private IStorageBackend storageBackend = new TemporaryStorageBackend();

    /**
     * Authentication Controller
     */
    @Wither
    private IAuthenticationController authenticationController = new DummyAuthController();

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
        CredentialManager credentialManager = new CredentialManager(this.storageBackend, this.authenticationController);

        return credentialManager;
    }
}
