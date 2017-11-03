package ro.kuberam.libs.java.crypto.digest;

import java.io.InputStream;

import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertTrue;

public class HashBinaryWithSha384 extends BaseTest {

    @Test
    public void hashBinaryWithSha384() throws Exception {
        try (final InputStream input = getClass().getResourceAsStream("../keystore.ks")) {
            final String result = Hash.hashBinary(input, "SHA-384", "base64");
            assertTrue(result.equals("DcQ3caBftiQCIQn96Pr8PC2vzs17Re0tZ8/CZnOoucu/N+818uqAXxR7l9oxYgoW"));
        }
    }
}
