package ro.kuberam.libs.java.crypto.encrypt;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import java.io.InputStream;

import static java.nio.charset.StandardCharsets.UTF_8;

public class EncryptStringWithAymmetricKey extends BaseTest {

    @Test
    public void encryptStringWithAesSymmetricKey() throws Exception {
        final String input = "Short string for tests.";
        try (final InputStream is = getClass().getResourceAsStream("../rsa-public-key.pub")) {
            final String publicKey = IOUtils.toString(is, UTF_8);

            final String result = AsymmetricEncryption.encryptString(input, publicKey,
                    "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

            System.out.println(result);
        }
    }

}
