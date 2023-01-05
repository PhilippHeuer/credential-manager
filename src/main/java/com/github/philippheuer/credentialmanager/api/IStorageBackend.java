package com.github.philippheuer.credentialmanager.api;

import com.github.philippheuer.credentialmanager.domain.Credential;

import java.util.Collection;
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
    Collection<Credential> loadCredentials();

    /**
     * Save the Credentials
     *
     * @param credentials List Credential
     */
    void saveCredentials(Collection<Credential> credentials);

    /**
     * Gets a Credential by UserId
     *
     * @param userId User Id
     * @return Credential
     */
    Optional<Credential> getCredentialByUserId(String userId);
}
