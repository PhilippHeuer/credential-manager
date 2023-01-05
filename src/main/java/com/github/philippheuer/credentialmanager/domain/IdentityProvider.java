package com.github.philippheuer.credentialmanager.domain;

import com.github.philippheuer.credentialmanager.CredentialManager;
import lombok.Data;
import lombok.Setter;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

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

    /**
     * is the provided credential valid?
     *
     * @param credential Credential
     * @return true if the credential is valid
     */
    public boolean isValid(Credential credential) {
        return true;
    }

    /**
     * renews a credential
     *
     * @param credential Credential
     * @return true on successful refresh
     */
    public boolean renew(Credential credential) {
        return false;
    }
}
