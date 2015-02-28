package ro.kuberam.libs.java.crypto.junit.encrypt;

import ro.kuberam.libs.java.crypto.encrypt.SymmetricEncryption;
import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class EncryptStringWithAesSymmetricKeyEcbMode extends BaseTest {

	@Test
	public void encryptStringWithAesSymmetricKey() throws Exception {
		String input = "Short string for tests.";
		String plainKey = "1234567890123456";
		
		String result = SymmetricEncryption.encryptString(input, plainKey, "AES", "", "SunJCE");

		Assert.assertTrue(result.equals("222-157-20-54-132-99-46-30-73-43-253-148-61-155-86-141-51-56-40-42-31-168-189-56-236-102-58-237-175-171-9-87"));
	}

}
