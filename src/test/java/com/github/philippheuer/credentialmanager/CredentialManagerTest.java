package com.github.philippheuer.credentialmanager;

import com.github.philippheuer.credentialmanager.domain.Credential;
import com.github.philippheuer.credentialmanager.domain.OAuth2Credential;
import com.github.philippheuer.credentialmanager.identityprovider.DefaultOAuth2IdentityProvider;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Slf4j
@Tag("unittest")
public class CredentialManagerTest {

    /**
     * Test Builder
     */
    @Test
    @DisplayName("CredentialManagerBuilder")
    public void builder() {
        // build
        CredentialManager credentialManager = CredentialManagerBuilder.builder().build();

        // asserts
        assertNotNull(credentialManager.getStorageBackend(), "Storage Backend not registered!");
    }

    /**
     * Test - Add Credential
     */
    @Test
    @DisplayName("Save a credential")
    public void saveCredential() {
        // build
        CredentialManager credentialManager = CredentialManagerBuilder.builder().build();
        credentialManager.registerIdentityProvider(new DefaultOAuth2IdentityProvider("default", "oauth2", null, null, null, null, null, null));

        // add credential
        Credential credential = new OAuth2Credential("default", "tokenHere");
        credentialManager.addCredential("default", credential);

        // asserts
        assertEquals(1, credentialManager.getCredentials().size(), "Credential wasn't added!");
    }

}
