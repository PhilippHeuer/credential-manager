package com.github.philippheuer.credentialmanager.storage;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.philippheuer.credentialmanager.api.IStorageBackend;
import com.github.philippheuer.credentialmanager.domain.Credential;
import lombok.Locked;
import lombok.SneakyThrows;
import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public class FileStorageBackend implements IStorageBackend {
    private final ObjectMapper objectMapper;
    private final File file;
    private List<Credential> credentials;

    @SneakyThrows
    public <T extends Credential> FileStorageBackend(@NotNull File file, @NotNull ObjectMapper mapper, @NotNull Class<T> credentialClass) {
        this.file = file;
        this.objectMapper = mapper.registerModule(new JavaTimeModule());

        if (file.exists() && file.length() > 0L) {
            List<T> creds = mapper.readValue(file, mapper.getTypeFactory().constructCollectionType(List.class, credentialClass));
            this.credentials = new ArrayList<>(creds);
        } else {
            this.credentials = new ArrayList<>();
        }
    }

    @Override
    @Locked.Read
    public List<Credential> loadCredentials() {
        return this.credentials;
    }

    @Override
    @SneakyThrows
    @Locked.Write
    public void saveCredentials(List<Credential> credentials) {
        if (credentials != null) {
            this.credentials = credentials;
        }

        objectMapper.writeValue(file, this.credentials);
    }

    @Override
    public Optional<Credential> getCredentialByUserId(String userId) {
        return credentials.stream().filter(c -> Objects.equals(userId, c.getUserId())).findAny();
    }
}
