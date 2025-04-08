package com.github.philippheuer.credentialmanager.util;

import lombok.experimental.UtilityClass;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.Nullable;

@UtilityClass
@ApiStatus.Internal
public class TokenResponseUtil {
    /**
     * Parses the expires_in attribute from a token response.
     *
     * @param value the object to parse
     * @return the parsed integer value, or null if the value is null
     * @throws IllegalArgumentException if the value is of an unexpected type or cannot be parsed
     */
    @Nullable
    public Integer parseExpiresIn(Object value) throws IllegalArgumentException {
        if (value instanceof Integer) {
            return (Integer) value;
        } else if (value instanceof String) {
            // not rfc compliant, but seen in the wild
            try {
                return Integer.parseInt((String) value);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid expires_in string value: " + value, e);
            }
        } else if (value == null) {
            return null;
        }

        throw new IllegalArgumentException("Unsupported expires_in type: " + value.getClass().getName());
    }
}
