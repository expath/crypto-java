package ro.kuberam.libs.java.crypto.junit.encrypt;

import ro.kuberam.libs.java.crypto.ErrorMessages;
import ro.kuberam.libs.java.crypto.digest.Hash;
import ro.kuberam.libs.java.crypto.encrypt.SymmetricEncryption;
import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class EncryptStringWithAesWrongSymmetricKeyAndDefaultProviderCbcMode extends BaseTest {

	@Test
	public void encryptStringWithAesWrongSymmetricKey() throws Exception {
		String input = "Short string for tests.";
		String plainKey = "12345678901234567";
		String iv = Hash.hashString("initialization vector", "MD5", "");		

		try {
			String result = SymmetricEncryption.encryptString(input, plainKey, "AES/CBC/PKCS5Padding", iv, "");
			Assert.assertTrue(false);
		} catch (Exception e) {
			Assert.assertTrue(e.getLocalizedMessage().equals(ErrorMessages.error_cryptoKey));
		}
	}
}
