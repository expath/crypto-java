package ro.kuberam.libs.java.crypto.junit.digest;

import java.io.InputStream;

import org.apache.commons.io.IOUtils;
import ro.kuberam.libs.java.crypto.digest.Hmac;
import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class HmacStringWithSha512 extends BaseTest {

	@Test
	public void hmacStringWithSha512() throws Exception {
		String input = "Short string for tests.";
		InputStream secretKeyIs = getClass().getResourceAsStream("../../private-key.pem");
	
		String result = Hmac.hmac(input, IOUtils.toString(secretKeyIs), "HMAC-SHA-512", "base64");

		Assert.assertTrue(result
				.equals("z9MtEpBXxO5bKmsXJWfKsZ4v+RduKU89Y95H2HMGQEwHGefWmewNNQ7urZVuWEU5aeRRdO7G7j0Q\r\nlcLYv1pkrg=="));
	}
}
