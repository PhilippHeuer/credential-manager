package com.github.philippheuer.credentialmanager.domain;

import lombok.Data;

import java.util.Map;

@Data
public class IdentityProvider {

    /**
     * Name of the Identity Provider
     */
    protected String providerName;

    /**
     * Authentication Method (OIDC/...)
     */
    protected String providerType;

    /**
     * Identity Provider Configuration
     */
    private Map<String, String> configuration;

}
