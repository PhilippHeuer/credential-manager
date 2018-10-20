package com.github.philippheuer.credentialmanager.api;

import com.github.philippheuer.credentialmanager.domain.Credential;

import java.util.List;

/**
 * Storage Backend Interface
 */
public interface IStorageBackend {

    /**
     * Load the Credentials
     *
     * @return List Credential
     */
    List<Credential> loadCredentials();

    /**
     * Save the Credentials
     *
     * @param credentials List Credential
     */
    void saveCredentials(List<Credential> credentials);

}
