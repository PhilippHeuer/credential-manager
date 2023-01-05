# *CredentialManager*

# Description

A simple OAuth Client & CredentialManager Library, that supports multiple storage backends.

# Import

| Module                                                                                                                                                                                                                              | Javadoc                                                                                                                                                                                                           |
|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [![Lib](https://img.shields.io/maven-central/v/com.github.philippheuer.credentialmanager/credentialmanager?label=credentialmanager)](https://search.maven.org/artifact/com.github.philippheuer.credentialmanager/credentialmanager) | [![Javadoc](https://javadoc.io/badge2/com.github.philippheuer.credentialmanager/credentialmanager/javadoc.svg?label=javadoc)](https://javadoc.io/doc/com.github.philippheuer.credentialmanager/credentialmanager) |

# Initialization

## Credential Manager

```groovy
CredentialManager credentialManager = CredentialManagerBuilder.builder()
    .withStorageBackend(new TemporaryStorageBackend())
    .build();
```

## Custom Storage Backends

This is an in-memory storage backend as an example. You can provide your own storage backend by supplying it in the builder to store/load the credentials from wherever you want.

```groovy
public class TemporaryStorageBackend implements IStorageBackend {

    /**
     * Holds the Credentials
     */
    private List<Credential> credentialStorage = new ArrayList<>();

    /**
     * Load the Credentials
     *
     * @return List Credential
     */
    public List<Credential> loadCredentials() {
        return this.credentialStorage;
    }

    /**
     * Save the Credentials
     *
     * @param credentials List Credential
     */
    public void saveCredentials(List<Credential> credentials) {
        this.credentialStorage = credentials;
    }
    
    /**
     * Gets a credential by user id
     *
     * @param userId User Id
     * @return Credential
     */
    public Optional<Credential> getCredentialByUserId(String userId) {
        for(Credential cred : credentialStorage) {
            if (cred.getUserId().equalsIgnoreCase(userId)) {
                return Optional.ofNullable(cred);
            }
        }

        return Optional.empty();
    }

}
```

## License

Released under the [MIT License](./LICENSE).
