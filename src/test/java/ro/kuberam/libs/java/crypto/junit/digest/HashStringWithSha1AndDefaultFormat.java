package ro.kuberam.libs.java.crypto.junit.digest;

import ro.kuberam.libs.java.crypto.digest.Hash;
import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class HashStringWithSha1AndDefaultFormat extends BaseTest {

	@Test
	public void hashStringWithSha1hexOutput() throws Exception {
		String input = "Short string for tests.";
		
		String result = Hash.hashString(input, "SHA-1");

		Assert.assertTrue(result
				.equals("cV2wx17vo8eH2TaFRvCIIvJjNqU="));		
	}
}
