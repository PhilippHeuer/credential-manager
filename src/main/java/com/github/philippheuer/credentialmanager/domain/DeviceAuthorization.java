package com.github.philippheuer.credentialmanager.domain;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import okhttp3.HttpUrl;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.HashMap;
import java.util.Map;

/**
 * The response from the device authorization request.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8628#section-3.2">RFC</a>
 */
@Data
@Setter(AccessLevel.PRIVATE)
@NoArgsConstructor
@AllArgsConstructor
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class DeviceAuthorization {

    /**
     * The device verification code.
     */
    @NotNull
    private String deviceCode;

    /**
     * The end-user verification code.
     */
    @NotNull
    private String userCode;

    /**
     * The end-user verification URI on the authorization server.
     */
    @NotNull
    private String verificationUri;

    /**
     * The lifetime in seconds of the {@link #getDeviceCode()} and {@link #getUserCode()}..
     */
    private int expiresIn;

    /**
     * The minimum amount of time in seconds that the client
     * should wait between polling requests to the token endpoint.
     */
    private int interval = 5; // RFC: "If no value is provided, clients MUST use 5 as the default."

    /**
     * A verification URI that includes the {@code user_code}
     * (or other information with the same function as the {@code user_code}),
     * which is designed for non-textual transmission.
     */
    @Nullable
    @Getter(AccessLevel.PROTECTED) // avoid confusion with #getCompleteUri
    private String verificationUriComplete;

    /**
     * Contains any non-standardized properties in the initial device authorization response.
     */
    @JsonAnyGetter
    @JsonAnySetter
    private Map<String, Object> customProperties = new HashMap<>(0);

    /**
     * @return the verification uri with the populated user_code query parameter.
     */
    public String getCompleteUri() {
        if (verificationUriComplete != null && !verificationUriComplete.isEmpty()) {
            return verificationUriComplete;
        }
        HttpUrl url = HttpUrl.parse(verificationUri);
        if (url == null) {
            return null; // should never happen for well-behaved auth services
        }
        // RFC explicitly recommends against including user_code in the verification URI
        // but just in case some auth service does this anyway, avoid duplicating query param
        if (this.userCode.equals(url.queryParameter("user_code"))) {
            return verificationUri;
        }
        // append user_code to the verification uri
        return url.newBuilder()
                .addQueryParameter("user_code", this.userCode)
                .build()
                .toString();
    }

}
