package ro.kuberam.libs.java.crypto.encrypt;

import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class EncryptStringWithAymmetricKey extends BaseTest {

	@Test
	public void encryptStringWithAesSymmetricKey() throws Exception {
		String input = "Short string for tests.";
		String publicKey = IOUtils.toString(getClass().getResourceAsStream("../rsa-public-key.pub"));

		String result = AsymmetricEncryption.encryptString(input, publicKey,
				"RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

		System.out.println(result);
	}

}
