package ro.kuberam.libs.java.crypto.digest;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.apache.commons.io.IOUtils;

import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertTrue;

public class HmacStringWithSha256AndDefaultFormat extends BaseTest {

    @Test
    public void hmacStringWithSha256() throws Exception {
        final String input = "Short string for tests.";
        try (final InputStream secretKeyIs = getClass().getResourceAsStream("../rsa-private-key.key")) {

            final String result = Hmac.hmac(input.getBytes(StandardCharsets.UTF_8), IOUtils.toByteArray(secretKeyIs),
                    "HMAC-SHA-256", "");

            assertTrue(result.equals("FfZidcLEUg4oJLIZfw6xHlPMz8KPHxo2liaBKgLfcOE="));
        }
    }
}
