package ro.kuberam.libs.java.crypto.junit.digest;

import java.io.InputStream;

import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.libs.java.crypto.digest.Hash;
import ro.kuberam.tests.junit.BaseTest;

public class HashBinaryWithMd5AndDefaultFormat extends BaseTest {

	@Test
	public void hashBinaryWithMd5() throws Exception {
		InputStream input = getClass().getResourceAsStream("../../keystore.ks");
		String result = Hash.hashBinary(input, "MD5");

		Assert.assertTrue(result.equals("UI/aOJodA6gtJPitQ6xcJA=="));
	}
}
