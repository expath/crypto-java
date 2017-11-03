package ro.kuberam.libs.java.crypto.digest;

import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertTrue;

public class HashStringWithSha512AndDefaultFormat extends BaseTest {

    @Test
    public void hashStringWithSha512hexOutput() throws Exception {
        final String input = "Short string for tests.";
        final String result = Hash.hashString(input, "SHA-512");
        assertTrue(result
                .equals("+YpeZRBrctlL1xr6plZOScp/6ArUw3GihjtKys1e3qQ6/aWLFjoOFEfuiUJA3uLIkebH1OG+rDdM\r\nFZ0+/JFK2g=="));
    }
}
