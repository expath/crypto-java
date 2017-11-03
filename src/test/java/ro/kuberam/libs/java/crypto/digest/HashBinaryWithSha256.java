package ro.kuberam.libs.java.crypto.digest;

import java.io.InputStream;

import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertTrue;

public class HashBinaryWithSha256 extends BaseTest {

    @Test
    public void hashBinaryWithSha256() throws Exception {
        try (final InputStream input = getClass().getResourceAsStream("../keystore.ks")) {
            final String result = Hash.hashBinary(input, "SHA-256", "base64");
            assertTrue(result.equals("37JiNBym250ye3aUJ04RaZg3SFSP03qJ8FR/I1JckVI="));
        }
    }
}
