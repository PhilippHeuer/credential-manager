package com.github.philippheuer.credentialmanager.authcontroller;

import com.github.philippheuer.credentialmanager.domain.DeviceAuthorization;
import com.github.philippheuer.credentialmanager.identityprovider.DefaultOAuth2IdentityProvider;
import com.github.philippheuer.credentialmanager.util.ProxyHelper;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

@Slf4j
class DeviceFlowControllerTest {

    @Test
    @Tag("integration")
    @Disabled
    void testTwitch() throws InterruptedException {
        DefaultOAuth2IdentityProvider ip = new DefaultOAuth2IdentityProvider("twitch", "oauth2", "ipfj51ut03jud7jqdy7em925dg7k2l", null, "https://id.twitch.tv/oauth2/authorize", "https://id.twitch.tv/oauth2/token", "https://id.twitch.tv/oauth2/device", null, "QUERY", ProxyHelper.selectProxy());
        CountDownLatch latch = new CountDownLatch(1);
        DeviceFlowController controller = new DeviceFlowController();
        DeviceAuthorization req = controller.startOAuth2DeviceAuthorizationGrantType(ip, Arrays.asList("user:read:email", "user:read:broadcast"), resp -> {
            log.info("Device Access Token callback triggered: {}", resp);
            latch.countDown();
        });
        log.debug(req.toString());
        log.info("The user should now visit: {}", req.getCompleteUri());
        latch.await(req.getExpiresIn(), TimeUnit.SECONDS);
        controller.close();
    }

}
