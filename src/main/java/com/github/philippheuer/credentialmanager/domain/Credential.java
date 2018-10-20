package com.github.philippheuer.credentialmanager.domain;

import lombok.Data;

@Data
public abstract class Credential {

    /**
     * The identity provider key
     */
    private String identityProvider;

}
