package ro.kuberam.libs.java.crypto.digest;

import java.io.InputStream;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertTrue;

public class HmacStringWithMd5 extends BaseTest {

    @Test
    public void hmacStringWithMd5() throws Exception {
        final String input = "Short string for tests.";
        try (final InputStream secretKeyIs = getClass().getResourceAsStream("../rsa-private-key.key")) {
            final String secretKey = IOUtils.toString(secretKeyIs, UTF_8);

            final String result = Hmac.hmac(input.getBytes(UTF_8),
                    secretKey.getBytes(UTF_8), "HMAC-MD5", "base64");

            assertTrue(result.equals("l4MY6Yosjo7W60VJeXB/PQ=="));
        }
    }
}
