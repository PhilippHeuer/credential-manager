package com.github.philippheuer.credentialmanager.storage;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.philippheuer.credentialmanager.domain.Credential;
import com.github.philippheuer.credentialmanager.domain.OAuth2Credential;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileStorageBackendTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static File file;
    private static Path path;

    @BeforeAll
    static void beforeAll() throws IOException {
        file = File.createTempFile("events4j-", "-storage-test.json");
        path = file.toPath();
    }

    @AfterAll
    static void afterAll() {
        if (!file.delete()) {
            file.deleteOnExit();
        }
    }

    @Test
    void readWriteEmpty() throws IOException {
        Files.write(path, new byte[0]);
        FileStorageBackend storage = new FileStorageBackend(file, OBJECT_MAPPER, OAuth2Credential.class);
        List<Credential> credentials = storage.loadCredentials();
        assertTrue(credentials.isEmpty());

        storage.saveCredentials(credentials);
        assertEquals(Collections.singletonList("[]"), Files.readAllLines(path));

        assertFalse(storage.getCredentialByUserId(null).isPresent());
    }

    @Test
    void readWrite() throws IOException {
        String json = "[{\"identity_provider\":\"test\",\"access_token\":\"asdf\"}]";
        Files.write(path, json.getBytes(StandardCharsets.UTF_8));

        FileStorageBackend storage = new FileStorageBackend(file, OBJECT_MAPPER, OAuth2Credential.class);
        List<Credential> credentials = storage.loadCredentials();
        assertEquals(1, credentials.size());

        OAuth2Credential actual = (OAuth2Credential) credentials.get(0);
        OAuth2Credential expected = new OAuth2Credential("test", "asdf");
        expected.setReceivedAt(actual.getReceivedAt());
        assertEquals(expected, actual);

        credentials.add(new OAuth2Credential("test", "qwerty"));
        storage.saveCredentials(credentials);

        String output = String.join("", Files.readAllLines(path));
        String expectedOutput = "[{\"identity_provider\":\"test\",\"access_token\":\"asdf\",\"scopes\":[],\"context\":{}},{\"identity_provider\":\"test\",\"access_token\":\"qwerty\",\"scopes\":[],\"context\":{}}]";
        assertEquals(expectedOutput, output);
    }

}
