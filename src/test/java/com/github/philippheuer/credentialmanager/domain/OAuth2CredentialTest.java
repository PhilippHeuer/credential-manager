package com.github.philippheuer.credentialmanager.domain;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class OAuth2CredentialTest {
    @Test
    void testUpdateCredential_ValuesAreUpdated() {
        OAuth2Credential originalCred = new OAuth2Credential("test", "original-token", "original-refresh", "userId", "userName", Instant.now(), 3600, null, null);
        OAuth2Credential updatedCred = new OAuth2Credential("test", "updated-token", "updated-refresh", "userId2", "userName2", Instant.ofEpochSecond(1743465600), 7200, null, null);

        originalCred.updateCredential(updatedCred);

        assertEquals("updated-token", originalCred.getAccessToken(), "Access token should be updated");
        assertEquals("updated-refresh", originalCred.getRefreshToken(), "Refresh token should be updated");
        assertEquals("userId2", originalCred.getUserId(), "User ID should not be updated");
        assertEquals("userName2", originalCred.getUserName(), "User name should not be updated");
        assertEquals(Instant.ofEpochSecond(1743465600), updatedCred.getIssuedAt(), "IssuedAt should not be updated");
        assertEquals(7200, originalCred.getExpiresIn(), "ExpiresIn should be updated");
    }

    @Test
    void testIsExpired_whenIssuedAtIsNull_returnsTrue() {
        OAuth2Credential credential = new OAuth2Credential("test", "token");
        credential.setIssuedAt(null);
        credential.setExpiresIn(3600);

        assertTrue(credential.isExpired(), "Token is considered expired when issuedAt is null");
    }

    @Test
    void testIsExpired_whenExpiresInIsNull_returnsFalse() {
        OAuth2Credential credential = new OAuth2Credential("test", "token");
        credential.setIssuedAt(Instant.now().minusSeconds(10_000));
        credential.setExpiresIn(null);

        assertFalse(credential.isExpired(), "Token should not expire when expiresIn is null");
    }

    @Test
    void testIsExpired_whenTokenIsStillValid_returnsFalse() {
        OAuth2Credential credential = new OAuth2Credential("test", "token");
        credential.setIssuedAt(Instant.now().minusSeconds(60)); // issued 1 minute ago
        credential.setExpiresIn(3600); // valid for 1 hour

        assertFalse(credential.isExpired(), "Token should not have expired yet");
    }

    @Test
    void testIsExpired_whenTokenHasExpired_returnsTrue() {
        OAuth2Credential credential = new OAuth2Credential("test", "token");
        credential.setIssuedAt(Instant.now().minusSeconds(7200)); // issued 2 hours ago
        credential.setExpiresIn(3600); // valid for 1 hour

        assertTrue(credential.isExpired(), "Token should have expired");
    }
}
