package com.github.philippheuer.credentialmanager.domain;

import lombok.Data;

@Data
public abstract class Credential {

    /**
     * The identity provider key
     */
    private final String identityProvider;

    /**
     * Constructor
     */
    public Credential(String identityProvider) {
        this.identityProvider = identityProvider;
    }
}
