package com.github.philippheuer.credentialmanager.domain;

import lombok.Data;

@Data
public abstract class Credential {

    /**
     * The identity provider key
     */
    private final String identityProvider;

    /**
     * Unique User Id
     */
    protected String userId;

    /**
     * Credential
     *
     * @param identityProvider Identity Provider
     * @param userId           User Id
     */
    public Credential(String identityProvider, String userId) {
        this.identityProvider = identityProvider;
        this.userId = userId;
    }
}
