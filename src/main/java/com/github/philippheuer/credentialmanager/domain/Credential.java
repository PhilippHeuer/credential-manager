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
    private final String userId;

    /**
     * Constructor
     */
    public Credential(String identityProvider, String userId) {
        this.identityProvider = identityProvider;
        this.userId = userId;
    }
}
