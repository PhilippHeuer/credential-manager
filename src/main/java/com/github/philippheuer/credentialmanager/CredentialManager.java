package com.github.philippheuer.credentialmanager;

import com.github.philippheuer.credentialmanager.api.IStorageBackend;
import com.github.philippheuer.credentialmanager.domain.Credential;
import com.github.philippheuer.credentialmanager.domain.IdentityProvider;
import com.github.philippheuer.credentialmanager.domain.OAuth2Credential;
import com.github.philippheuer.credentialmanager.identityprovider.OAuth2IdentityProvider;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * The CredentialManager
 */
@Getter
@Slf4j
public class CredentialManager {

    /**
     * Storage Backend
     */
    private final IStorageBackend storageBackend;

    /**
     * Holds the registered identity providers
     */
    private final List<IdentityProvider> identityProviders = new ArrayList<>();

    /**
     * In-Memory Credential Storage
     */
    private List<Credential> credentials;

    /**
     * Creates a new CredentialManager
     *
     * @param storageBackend The Storage Backend
     */
    public CredentialManager(IStorageBackend storageBackend) {
        this.storageBackend = storageBackend;

        // load credentials
        this.load();
    }

    /**
     * Registers a new Identity Provider
     */
    public void registerIdentityProvider(IdentityProvider identityProvider) {
        Boolean exists = this.identityProviders.stream().filter(idp -> idp.getProviderName().equalsIgnoreCase(identityProvider.getProviderName())).count() > 0 ? true : false;
        if (exists) {
            throw new RuntimeException("Identity Provider " + identityProvider.getProviderName() + " was already registered!");
        }

        this.identityProviders.add(identityProvider);
    }

    /**
     * Adds a Credential
     */
    public void addCredential(String providerName, Credential credential) {
        // OAuth2
        if (credential instanceof OAuth2Credential) {
            OAuth2Credential oAuth2Credential = (OAuth2Credential) credential;
            List<IdentityProvider> oauth2IdentityProviders = this.identityProviders.stream().filter(idp -> idp.getProviderType().equalsIgnoreCase("oauth2") && idp.getProviderName().equalsIgnoreCase(providerName) && idp instanceof OAuth2IdentityProvider).collect(Collectors.toList());

            if (oauth2IdentityProviders.size() >= 1) {
                OAuth2IdentityProvider oAuth2IdentityProvider = (OAuth2IdentityProvider) oauth2IdentityProviders.get(0);

                Optional<OAuth2Credential> enrichedCredential = oAuth2IdentityProvider.getTokenInformation(oAuth2Credential.getAuthToken());
                if (enrichedCredential.isPresent()) {
                    credential = enrichedCredential.get();
                }
            }
        }

        this.credentials.add(credential);
    }

    /**
     * Gets a OAuth2Credential by UserId
     *
     * @param userId User Id
     */
    public Optional<OAuth2Credential> getOAuth2CredentialByUserId(String userId) {
        for (Credential entry : this.credentials) {
            if (entry instanceof OAuth2Credential) {
                OAuth2Credential credential = (OAuth2Credential) entry;

                if (credential.getUserId().equalsIgnoreCase(userId)) {
                    return Optional.ofNullable(credential);
                }
            }
        }

        return Optional.empty();
    }

    /**
     * Loads the Credentials from the Storage Backend
     */
    public void load() {
        this.credentials = storageBackend.loadCredentials();
    }

    /**
     * Persist the Credentials into the Storage Backend
     */
    public void save() {
        this.storageBackend.saveCredentials(credentials);
    }

}
