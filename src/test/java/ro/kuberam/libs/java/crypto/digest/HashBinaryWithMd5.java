package ro.kuberam.libs.java.crypto.digest;

import java.io.InputStream;

import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertTrue;

public class HashBinaryWithMd5 extends BaseTest {

    @Test
    public void hashBinaryWithMd5() throws Exception {
        try (final InputStream input = getClass().getResourceAsStream("../keystore.ks")) {
            final String result = Hash.hashBinary(input, "MD5", "base64");
            assertTrue(result.equals("UI/aOJodA6gtJPitQ6xcJA=="));
        }
    }
}
