package ro.kuberam.libs.java.crypto.junit.encrypt;

import ro.kuberam.libs.java.crypto.digest.Hash;
import ro.kuberam.libs.java.crypto.encrypt.SymmetricEncryption;
import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class DecryptStringWithAesSymmetricKeyAndDefaultProviderCbcMode extends BaseTest {

	@Test
	public void decryptStringWithAesSymmetricKey() throws Exception {
		String input = "51-143-171-200-187-20-34-252-231-243-254-42-36-13-9-123-191-251-243-42-3-238-193-13-155-168-139-67-135-3-143-54";
		String plainKey = "1234567890123456";
		String iv = Hash.hashString("initialization vector", "MD5", "");
		
		String result = SymmetricEncryption.decryptString(input, plainKey, "AES/CBC/PKCS5Padding", iv, "");

		Assert.assertTrue(result.equals("Short string for tests."));
	}
}
