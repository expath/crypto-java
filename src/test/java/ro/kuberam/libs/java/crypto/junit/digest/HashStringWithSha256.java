package ro.kuberam.libs.java.crypto.junit.digest;

import ro.kuberam.libs.java.crypto.digest.Hash;
import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class HashStringWithSha256 extends BaseTest {

	@Test
	public void hashStringWithSha256hexOutput() throws Exception {
		String input = "Short string for tests.";
		
		String result = Hash.hashString(input, "SHA-256", "base64");

		Assert.assertTrue(result
				.equals("E+B0JzLRgxm2+1rB8qIZoQ2Qn+JLxwJCWORv46fKhMM="));
	}
}
