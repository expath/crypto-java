package ro.kuberam.libs.java.crypto.junit.digest;

import java.io.InputStream;

import org.apache.commons.io.IOUtils;
import ro.kuberam.libs.java.crypto.ExpathCryptoModule;
import ro.kuberam.libs.java.crypto.digest.Hmac;
import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class HmacStringWithMd5 extends BaseTest {

	@Test
	public void hmacStringWithMd5() throws Exception {
		String input = "Short string for tests.";
		InputStream secretKeyIs = getClass().getResourceAsStream("../../private-key.pem");
		String secretKey = IOUtils.toString(secretKeyIs);

		String result = Hmac.hmac(input, secretKey, "HMAC-MD5", "base64");

		Assert.assertTrue(result
				.equals("l4MY6Yosjo7W60VJeXB/PQ=="));
	}
}
