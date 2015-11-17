package ro.kuberam.libs.java.crypto.digest;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.apache.commons.io.IOUtils;

import ro.kuberam.libs.java.crypto.digest.Hmac;

import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class HmacStringWithSha256AndDefaultFormat extends BaseTest {

	@Test
	public void hmacStringWithSha256() throws Exception {
		String input = "Short string for tests.";
		InputStream secretKeyIs = getClass().getResourceAsStream("../rsa-private-key.key");

		String result = Hmac.hmac(input.getBytes(StandardCharsets.UTF_8), IOUtils.toByteArray(secretKeyIs),
				"HMAC-SHA-256", "");

		Assert.assertTrue(result.equals("FfZidcLEUg4oJLIZfw6xHlPMz8KPHxo2liaBKgLfcOE="));
	}
}
