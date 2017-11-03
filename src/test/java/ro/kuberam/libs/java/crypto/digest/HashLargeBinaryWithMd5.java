package ro.kuberam.libs.java.crypto.digest;

import java.io.InputStream;
import java.nio.file.Files;

import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class HashLargeBinaryWithMd5 extends BaseTest {

    @Test
    public void hashLargeBinaryWithMd5() throws Exception {
        try (final InputStream is = Files.newInputStream(generate5MbTempFile().toPath())) {
            final String result = Hash.hashBinary(is, "MD5", "base64");
            Assert.assertTrue(result.equals("fSAcOQGKiTzr20UUJWNpaQ=="));
        }
    }
}
