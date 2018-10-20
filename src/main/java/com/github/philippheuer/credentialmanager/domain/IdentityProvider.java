package com.github.philippheuer.credentialmanager.domain;

import lombok.Data;

import java.util.Map;

@Data
public class IdentityProvider {

    /**
     * Name of the Identity Provider
     */
    private String name;

    /**
     * Authentication Method (OIDC/...)
     */
    private String type;

    /**
     * Identity Provider Configuration
     */
    private Map<String, String> configuration;

}
