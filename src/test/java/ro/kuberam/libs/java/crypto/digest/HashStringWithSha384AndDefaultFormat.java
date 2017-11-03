package ro.kuberam.libs.java.crypto.digest;

import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertTrue;

public class HashStringWithSha384AndDefaultFormat extends BaseTest {

    @Test
    public void hashStringWithSha384hexOutput() throws Exception {
        final String input = "Short string for tests.";
        final String result = Hash.hashString(input, "SHA-384");
        assertTrue(result
                .equals("F4CFDSBHm+Bm400bOgH2q2IbIUj8XRUBWf0inx7lrN0T8IHz9scGVmJoGZ2+s1La"));
    }
}
