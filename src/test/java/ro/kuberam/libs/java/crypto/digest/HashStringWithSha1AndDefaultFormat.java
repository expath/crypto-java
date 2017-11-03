package ro.kuberam.libs.java.crypto.digest;

import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertTrue;

public class HashStringWithSha1AndDefaultFormat extends BaseTest {

    @Test
    public void hashStringWithSha1hexOutput() throws Exception {
        final String input = "Short string for tests.";
        final String result = Hash.hashString(input, "SHA-1");
        assertTrue(result
                .equals("cV2wx17vo8eH2TaFRvCIIvJjNqU="));
    }
}
