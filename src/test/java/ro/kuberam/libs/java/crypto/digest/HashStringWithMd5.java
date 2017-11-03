package ro.kuberam.libs.java.crypto.digest;

import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertTrue;

public class HashStringWithMd5 extends BaseTest {

    @Test
    public void hashStringWithMd5hexOutput() throws Exception {
        final String input = "Short string for tests.";
        final String result = Hash.hashString(input, "MD5", "base64");
        assertTrue(result
                .equals("use1oAoe8vIgnFgygz2OKw=="));
    }
}
