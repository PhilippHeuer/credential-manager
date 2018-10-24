package com.github.philippheuer.credentialmanager.api;

import com.github.philippheuer.credentialmanager.domain.Credential;

import java.util.List;
import java.util.Optional;

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

    /**
     * Gets a Credential by UserId
     *
     * @param userId User Id
     * @return Credential
     */
    Optional<Credential> getCredentialByUserId(String userId);
}
