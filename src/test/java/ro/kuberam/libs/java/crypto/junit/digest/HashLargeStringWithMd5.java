package ro.kuberam.libs.java.crypto.junit.digest;

import org.apache.commons.io.IOUtils;
import ro.kuberam.libs.java.crypto.digest.Hash;
import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class HashLargeStringWithMd5 extends BaseTest {

	@Test
	public void hashLargeStringWithMd5() throws Exception {
		String result = Hash.hashString(generate5MbTempString(), "MD5", "base64");
		
		System.out.println(result);

		Assert.assertTrue(result.equals("0oZeT8dy8rR/aqDYUz3sCw=="));
	}
}
