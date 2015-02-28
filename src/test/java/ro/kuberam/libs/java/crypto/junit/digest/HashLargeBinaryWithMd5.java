package ro.kuberam.libs.java.crypto.junit.digest;

import java.io.FileInputStream;

import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.libs.java.crypto.digest.Hash;
import ro.kuberam.tests.junit.BaseTest;

public class HashLargeBinaryWithMd5 extends BaseTest {

	@Test
	public void hashLargeBinaryWithMd5() throws Exception {
		String result = Hash.hashBinary(new FileInputStream(generate5MbTempFile()), "MD5", "base64");
		
		System.out.println(result);

		Assert.assertTrue(result.equals("fSAcOQGKiTzr20UUJWNpaQ=="));
	}
}
