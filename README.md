# *CredentialManager*

# Description

A simple OAuth Client & CredentialManager Library, that supports multiple storage backends.

# Import

Maven:

Add the repository to your pom.xml with:
```xml
<repositories>
    <repository>
      <id>jcenter</id>
      <url>https://jcenter.bintray.com/</url>
    </repository>
</repositories>
```
and the dependency: (latest, you should use the actual version here)

```xml
<dependency>
    <groupId>com.github.philippheuer.credentialmanager</groupId>
    <artifactId>credentialmanager</artifactId>
    <version>0.0.6</version>
    <type>pom</type>
</dependency>
```

Gradle:

Add the repository to your build.gradle with:
```groovy
repositories {
	jcenter()
}
```

and the dependency:
```groovy
compile 'com.github.philippheuer.credentialmanager:credentialmanager:0.0.5'
```

# Initialization

## Credential Manager

```groovy
CredentialManager credentialManager = CredentialManagerBuilder.builder()
    .withStorageBackend(new TemporaryStorageBackend())
    .build();
```

## Custom Storage Backends

This is a in-memory storage backend as example, you can use your own as supplied in the builder to store/load the credentials from whereever you want.

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
