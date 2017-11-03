package ro.kuberam.libs.java.crypto.digest;

import java.nio.file.Files;

import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertTrue;

public class HmacLargeBinaryWithSha1 extends BaseTest {

    @Test
    public void hmacLargeBinaryWithSha1() throws Exception {
        final String input = new String(Files.readAllBytes(generate5MbTempFile().toPath()), UTF_8);
        String secretKey = "/hWLmb8xRM75bOS6fyV9Pn0mf3Aiw+HphRCL8nOq";
        String result = Hmac.hmac(input.getBytes(UTF_8),
                secretKey.getBytes(UTF_8), "HMAC-SHA-1", "base64");

        System.out.println(result);

        assertTrue(result.equals("McKrpaWMrn0fzAlfw0yVDxy9esE="));
    }
}
