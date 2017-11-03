package ro.kuberam.libs.java.crypto.digest;

import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertTrue;

public class HashLargeStringWithMd5 extends BaseTest {

    @Test
    public void hashLargeStringWithMd5() throws Exception {
        final String result = Hash.hashString(generate5MbTempString(), "MD5", "base64");
        System.out.println(result);
        assertTrue(result.equals("0oZeT8dy8rR/aqDYUz3sCw=="));
    }
}
