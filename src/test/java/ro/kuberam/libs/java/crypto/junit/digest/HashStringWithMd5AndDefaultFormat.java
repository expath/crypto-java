package ro.kuberam.libs.java.crypto.junit.digest;

import ro.kuberam.libs.java.crypto.digest.Hash;
import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class HashStringWithMd5AndDefaultFormat extends BaseTest {

	@Test
	public void hashStringWithMd5hexOutput() throws Exception {
		String input = "Short string for tests.";
		
		String result = Hash.hashString(input, "MD5");

		Assert.assertTrue(result
				.equals("use1oAoe8vIgnFgygz2OKw=="));		
	}
}
