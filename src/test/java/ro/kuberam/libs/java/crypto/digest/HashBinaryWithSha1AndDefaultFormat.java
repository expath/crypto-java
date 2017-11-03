package ro.kuberam.libs.java.crypto.digest;

import java.io.InputStream;

import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertTrue;

public class HashBinaryWithSha1AndDefaultFormat extends BaseTest {

    @Test
    public void hashBinaryWithSha1() throws Exception {
        try (final InputStream input = getClass().getResourceAsStream("../keystore.ks")) {
            final String result = Hash.hashBinary(input, "SHA-1");
            assertTrue(result.equals("GyscHvnJKxInsBLgSg/FRAmQXYU="));
        }
    }
}
