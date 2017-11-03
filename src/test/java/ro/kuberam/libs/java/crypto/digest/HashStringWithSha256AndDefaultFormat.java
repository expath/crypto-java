package ro.kuberam.libs.java.crypto.digest;

import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertTrue;

public class HashStringWithSha256AndDefaultFormat extends BaseTest {

    @Test
    public void hashStringWithSha256hexOutput() throws Exception {
        final String input = "Short string for tests.";
        final String result = Hash.hashString(input, "SHA-256");
        assertTrue(result
                .equals("E+B0JzLRgxm2+1rB8qIZoQ2Qn+JLxwJCWORv46fKhMM="));
    }
}
