plugins {
    `java-library`
    id("me.philippheuer.configuration") version "0.11.2"
}

version = properties["version"] as String

projectConfiguration {
    type.set(me.philippheuer.projectcfg.domain.ProjectType.LIBRARY)
    javaVersion.set(JavaVersion.VERSION_1_8)
    artifactGroupId.set("com.github.philippheuer.credentialmanager")
    artifactId.set("credentialmanager")
    artifactDisplayName.set("credentialmanager")
    artifactDescription.set("A simple credential manager.")

    pom = { pom ->
        pom.url.set("https://github.com/PhilippHeuer/credential-manager")
        pom.issueManagement {
            system.set("GitHub")
            url.set("https://github.com/PhilippHeuer/credential-manager/issues")
        }
        pom.inceptionYear.set("2018")
        pom.developers {
            developer {
                id.set("PhilippHeuer")
                name.set("Philipp Heuer")
                email.set("git@philippheuer.me")
                roles.addAll("maintainer")
            }
        }
        pom.licenses {
            license {
                name.set("MIT Licence")
                distribution.set("repo")
                url.set("https://github.com/PhilippHeuer/credential-manager/blob/main/LICENSE")
            }
        }
        pom.scm {
            connection.set("scm:git:git://github.com/PhilippHeuer/credential-manager.git")
            developerConnection.set("scm:git:git://github.com/PhilippHeuer/credential-manager.git")
            url.set("https://github.com/PhilippHeuer/credential-manager")
        }
    }
}

dependencies {
    // Jackson (JSON)
    api("com.fasterxml.jackson.core:jackson-databind:2.17.2")

    // Logging
    api("org.slf4j:slf4j-api:2.0.16")
    testImplementation("org.slf4j:slf4j-simple:2.0.16")

    // Commons Lang
    implementation("org.apache.commons:commons-lang3:3.17.0")

    // HTTP Client
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")
}
