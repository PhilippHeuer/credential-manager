package com.github.philippheuer.credentialmanager;

import com.github.philippheuer.credentialmanager.api.IStorageBackend;
import com.github.philippheuer.credentialmanager.domain.Credential;
import com.github.philippheuer.credentialmanager.domain.IdentityProvider;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;

/**
 * The CredentialManager
 */
@Getter
@Slf4j
public class CredentialManager {

    /**
     * Storage Backend
     */
    private final IStorageBackend storageBackend;

    /**
     * Holds the registered identity providers
     */
    private final List<IdentityProvider> identityProviders = new ArrayList<>();

    /**
     * In-Memory Credential Storage
     */
    private List<Credential> credentials;

    /**
     * Creates a new CredentialManager
     *
     * @param storageBackend The Storage Backend
     */
    public CredentialManager(IStorageBackend storageBackend) {
        this.storageBackend = storageBackend;

        // load credentials
        this.load();
    }

    /**
     * Registers a new Identity Provider
     */
    public void registerIdentityProvider(IdentityProvider identityProvider) {
        this.identityProviders.add(identityProvider);
    }

    /**
     * Loads the Credentials from the Storage Backend
     */
    public void load() {
        this.credentials = storageBackend.loadCredentials();
    }

    /**
     * Persist the Credentials into the Storage Backend
     */
    public void save() {
        this.storageBackend.saveCredentials(credentials);
    }

}
