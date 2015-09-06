package ro.kuberam.libs.java.crypto.encrypt;

import java.io.InputStream;

import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class EncryptStringWithAymmetricKey extends BaseTest {

	@Test
	public void encryptStringWithAesSymmetricKey() throws Exception {
		String input = "Short string for tests.";
		String publicKey = IOUtils.toString(getClass().getResourceAsStream("../rsa-private-key.key"));
		
		String result = AsymmetricEncryption.encryptString(input, publicKey), "RSA");
		
		System.out.println(result);

		Assert.assertTrue(result.equals("222-157-20-54-132-99-46-30-73-43-253-148-61-155-86-141-51-56-40-42-31-168-189-56-236-102-58-237-175-171-9-87"));
	}

}
