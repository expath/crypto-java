package ro.kuberam.libs.java.crypto.junit.digest;

import ro.kuberam.libs.java.crypto.digest.Hash;
import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class HashStringWithSha384 extends BaseTest {

	@Test
	public void hashStringWithSha384hexOutput() throws Exception {
		String input = "Short string for tests.";
		
		String result = Hash.hashString(input, "SHA-384", "base64");

		Assert.assertTrue(result
				.equals("F4CFDSBHm+Bm400bOgH2q2IbIUj8XRUBWf0inx7lrN0T8IHz9scGVmJoGZ2+s1La"));
	}
}
