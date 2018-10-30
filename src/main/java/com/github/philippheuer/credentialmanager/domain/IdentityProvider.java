package com.github.philippheuer.credentialmanager.domain;

import com.github.philippheuer.credentialmanager.CredentialManager;
import lombok.Data;
import lombok.Setter;

import java.util.Map;

@Data
public class IdentityProvider {

    /**
     * Credential Manager
     */
    @Setter
    protected CredentialManager credentialManager;

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
    protected Map<String, String> configuration;

}
