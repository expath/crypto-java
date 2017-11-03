package ro.kuberam.libs.java.crypto.digest;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.apache.commons.io.IOUtils;

import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertTrue;

public class HmacStringWithSha1 extends BaseTest {

    @Test
    public void hmacStringWithSha1() throws Exception {
        final String input = "Short string for tests.";
        try (final InputStream secretKeyIs = getClass().getResourceAsStream("../rsa-private-key.key")) {

            final String result = Hmac.hmac(input.getBytes(StandardCharsets.UTF_8), IOUtils.toByteArray(secretKeyIs),
                    "HMAC-SHA-1", "base64");

            assertTrue(result.equals("55LyDq7GFnqijauK4CQWR4AqyZk="));
        }
    }
}
