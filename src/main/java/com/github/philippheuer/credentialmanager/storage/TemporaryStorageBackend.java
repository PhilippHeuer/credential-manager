package com.github.philippheuer.credentialmanager.storage;

import com.github.philippheuer.credentialmanager.api.IStorageBackend;
import com.github.philippheuer.credentialmanager.domain.Credential;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;

public class TemporaryStorageBackend implements IStorageBackend {

    /**
     * Holds the Credentials
     */
    private Collection<Credential> credentialStorage = new ArrayList<>();

    /**
     * Load the Credentials
     *
     * @return List Credential
     */
    public Collection<Credential> loadCredentials() {
        return this.credentialStorage;
    }

    /**
     * Save the Credentials
     *
     * @param credentials List Credential
     */
    public void saveCredentials(Collection<Credential> credentials) {
        this.credentialStorage = credentials;
    }

    /**
     * Gets a credential by user id
     *
     * @param userId User Id
     * @return Credential
     */
    public Optional<Credential> getCredentialByUserId(String userId) {
        for (Credential cred : credentialStorage) {
            if (cred.getUserId().equalsIgnoreCase(userId)) {
                return Optional.ofNullable(cred);
            }
        }

        return Optional.empty();
    }

}
