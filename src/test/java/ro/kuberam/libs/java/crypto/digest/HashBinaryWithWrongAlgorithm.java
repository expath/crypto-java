package ro.kuberam.libs.java.crypto.digest;

import java.io.InputStream;

import ro.kuberam.libs.java.crypto.ErrorMessages;
import ro.kuberam.libs.java.crypto.digest.Hash;
import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class HashBinaryWithWrongAlgorithm extends BaseTest {

	@Test
	public void hashBinaryWithWrongAlgorithm() throws Exception {
		InputStream input = getClass().getResourceAsStream("../../keystore.ks");
		
		try {
			String result = Hash.hashBinary(input, "SHA-17", "base64");
			Assert.assertTrue(false);
		} catch (Exception e) {
			Assert.assertTrue(e.getLocalizedMessage().equals(ErrorMessages.error_unknownAlgorithm));
		}
	}
}
