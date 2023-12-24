package com.github.philippheuer.credentialmanager.domain;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DeviceAuthorizationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Twitch's Device Authorization response deviates from the RFC in that:
     * <ul>
     *     <li>The {@code verification_uri} includes the {@code user_code} value, despite the RFC recommending against this</li>
     *     <li>The {@code verification_uri} calls the value associated with {@code user_code} as {@code device-code}</li>
     * </ul>
     * Regardless, the output of {@link DeviceAuthorization#getCompleteUri()} works as expected in the browser.
     *
     * @see <a href="https://dev.twitch.tv/docs/authentication/getting-tokens-oauth/#device-code-grant-flow">Twitch Documentation</a>
     */
    @Test
    void deserializeTwitch() throws JsonProcessingException {
        String json = "{\"device_code\":\"helloWorld\",\"expires_in\":1800,\"interval\":5,\"user_code\":\"ABCDEFGH\"," +
                "\"verification_uri\":\"https://www.twitch.tv/activate?device-code=ABCDEFGH\"}";
        DeviceAuthorization resp = MAPPER.readValue(json, DeviceAuthorization.class);
        assertEquals("helloWorld", resp.getDeviceCode());
        assertEquals("ABCDEFGH", resp.getUserCode());
        assertEquals(1800, resp.getExpiresIn());
        assertEquals(5, resp.getInterval());
        assertEquals("https://www.twitch.tv/activate?device-code=ABCDEFGH", resp.getVerificationUri());
        assertEquals("https://www.twitch.tv/activate?device-code=ABCDEFGH&user_code=ABCDEFGH", resp.getCompleteUri());
        assertTrue(resp.getCustomProperties().isEmpty());
    }

    @Test
    void deserializeCustom() throws JsonProcessingException {
        String json = "{\"device_code\":\"helloWorld\",\"expires_in\":1800,\"interval\":5,\"user_code\":\"ABCDEFGH\"," +
                "\"verification_uri\":\"https://activate.example.com\",\"foo\":\"bar\",\"bar\":\"baz\"}";
        DeviceAuthorization resp = MAPPER.readValue(json, DeviceAuthorization.class);
        assertEquals(2, resp.getCustomProperties().size());
        assertEquals("bar", resp.getCustomProperties().get("foo"));
        assertEquals("baz", resp.getCustomProperties().get("bar"));
    }

}
