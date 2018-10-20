package com.github.philippheuer.credentialmanager.storage;

import com.github.philippheuer.credentialmanager.api.IStorageBackend;
import com.github.philippheuer.credentialmanager.domain.Credential;

import java.util.ArrayList;
import java.util.List;

public class TemporaryStorageBackend implements IStorageBackend {

    /**
     * Holds the Credentials
     */
    private List<Credential> credentialStorage = new ArrayList<>();

    /**
     * Load the Credentials
     *
     * @return List Credential
     */
    public List<Credential> loadCredentials() {
        return this.credentialStorage;
    }

    /**
     * Save the Credentials
     *
     * @param credentials List Credential
     */
    public void saveCredentials(List<Credential> credentials) {
        this.credentialStorage = credentials;
    }

}
