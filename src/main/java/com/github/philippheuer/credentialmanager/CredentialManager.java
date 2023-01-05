package com.github.philippheuer.credentialmanager;

import com.github.philippheuer.credentialmanager.api.IStorageBackend;
import com.github.philippheuer.credentialmanager.domain.AuthenticationController;
import com.github.philippheuer.credentialmanager.domain.Credential;
import com.github.philippheuer.credentialmanager.domain.IdentityProvider;
import com.github.philippheuer.credentialmanager.domain.OAuth2Credential;
import com.github.philippheuer.credentialmanager.identityprovider.OAuth2IdentityProvider;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Synchronized;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
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
     * Authentication Controller
     */
    private final AuthenticationController authenticationController;

    /**
     * Holds the registered identity providers
     */
    @Getter(AccessLevel.PROTECTED)
 	private final Map<String, IdentityProvider> identityProvidersByLowerName = new ConcurrentHashMap<>();

    /**
     * In-Memory Credential Storage
     */
    private List<Credential> credentials;

    /**
     * Creates a new CredentialManager
     *
     * @param storageBackend           The Storage Backend
     * @param authenticationController Authentication Controller
     */
    public CredentialManager(IStorageBackend storageBackend, AuthenticationController authenticationController) {
        this.storageBackend = storageBackend;
        this.authenticationController = authenticationController;
        authenticationController.setCredentialManager(this);

        // load credentials
        this.load();
    }

    /**
     * Registers a new Identity Provider
     *
     * @param identityProvider Identity Provider
     * @throws RuntimeException if there was another provider registered with the same name, but different class representation
     */
    public void registerIdentityProvider(IdentityProvider identityProvider) {
        log.debug("Trying to register IdentityProvider {} [Type: {}]", identityProvider.getProviderName(), identityProvider.getProviderType());

        String lowerName = identityProvider.getProviderName().toLowerCase();
        IdentityProvider previous = identityProvidersByLowerName.putIfAbsent(lowerName, identityProvider);

        if (previous != null) {
            String msg = "Identity Provider " + identityProvider.getProviderName() + " was already registered!";
            if (identityProvider.getClass().isAssignableFrom(previous.getClass())) {
                // we already have registered an identity provider with this name and (super)class; no need for an exception
                log.info(msg);
                return;
            }
            if (!previous.getClass().isAssignableFrom(identityProvider.getClass()) || !identityProvidersByLowerName.replace(identityProvider.getProviderName().toLowerCase(), previous, identityProvider)) {
                // tried to register provider with same name and completely different class hierarchy; throw error
                throw new RuntimeException(msg);
            }
        }

        identityProvider.setCredentialManager(this);
        log.debug("Registered IdentityProvider {} [Type: {}]", identityProvider.getProviderName(), identityProvider.getProviderType());
        log.debug("A total of {} IdentityProviders have been registered!", this.identityProvidersByLowerName.size());
    }

    /**
     * Get all registered identity providers
     *
     * @return a list of all registered identity providers
     */
    public List<IdentityProvider> getIdentityProviders() {
        return Collections.unmodifiableList(new ArrayList<>(identityProvidersByLowerName.values()));
    }

    /**
     * Get Identity Provider by Name
     *
     * @param identityProviderName Identity Provider Name
     * @return IdentityProvider
     */
    public Optional<IdentityProvider> getIdentityProviderByName(String identityProviderName) {
        return Optional.ofNullable(identityProvidersByLowerName.get(identityProviderName.toLowerCase()));
    }

    /**
     * Get OAuth2 Identity Provider by Name
     *
     * @param identityProviderName Identity Provider Name
     * @return IdentityProvider
     */
    public <T> Optional<T> getIdentityProviderByName(String identityProviderName, Class<T> identityProviderClass) {
        return getIdentityProviderByName(identityProviderName)
                .filter(i -> identityProviderClass.isAssignableFrom(i.getClass()))
                .map(identityProviderClass::cast);
    }

    /**
     * Get OAuth2 Identity Provider by Name
     *
     * @param identityProviderName Identity Provider Name
     * @return IdentityProvider
     */
    public Optional<OAuth2IdentityProvider> getOAuth2IdentityProviderByName(String identityProviderName) {
        return getIdentityProviderByName(identityProviderName).filter(i -> i instanceof OAuth2IdentityProvider).map(i -> (OAuth2IdentityProvider) i);
    }

    /**
     * Adds a Credential
     *
     * @param providerName Provider Name
     * @param credential   Credential
     */
    public void addCredential(String providerName, Credential credential) {
        // OAuth2
        if (credential instanceof OAuth2Credential) {
            OAuth2Credential oAuth2Credential = (OAuth2Credential) credential;

            OAuth2IdentityProvider oAuth2IdentityProvider = getIdentityProviderByName(providerName)
                .filter(idp -> idp.getProviderType().equalsIgnoreCase("oauth2") && idp instanceof OAuth2IdentityProvider)
                .map(idp -> (OAuth2IdentityProvider) idp)
                .orElseThrow(() -> new RuntimeException("Can't find a unique identity provider for the specified credential!"));

            Optional<OAuth2Credential> enrichedCredential = oAuth2IdentityProvider.getAdditionalCredentialInformation(oAuth2Credential);
            if (enrichedCredential.isPresent()) {
                credential = enrichedCredential.get();
            }
        }

        this.credentials.add(credential);
    }

    /**
     * Gets a OAuth2Credential by UserId
     *
     * @param userId User Id
     * @return OAuth2Credential
     */
    public Optional<OAuth2Credential> getOAuth2CredentialByUserId(@NotNull String userId) {
        for (Credential entry : this.credentials) {
            if (entry instanceof OAuth2Credential) {
                OAuth2Credential credential = (OAuth2Credential) entry;

                if (userId.equalsIgnoreCase(credential.getUserId())) {
                    return Optional.of(credential);
                }
            }
        }

        return Optional.empty();
    }

    /**
     * Loads the Credentials from the Storage Backend
     */
    @Synchronized
    public void load() {
        this.credentials = storageBackend.loadCredentials();
    }

    /**
     * Persist the Credentials into the Storage Backend
     */
    @Synchronized
    public void save() {
        this.storageBackend.saveCredentials(credentials);
    }
}
