package ro.kuberam.libs.java.crypto.digest;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.libs.java.crypto.digest.Hmac;
import ro.kuberam.tests.junit.BaseTest;

public class HmacStringWithMd5AndDefaultFormat extends BaseTest {

	@Test
	public void hmacStringWithMd5() throws Exception {
		String input = "Short string for tests.";
		InputStream secretKeyIs = getClass().getResourceAsStream("../rsa-private-key.key");
		String secretKey = IOUtils.toString(secretKeyIs);

		String result = Hmac.hmac(input.getBytes(StandardCharsets.UTF_8),
				secretKey.getBytes(StandardCharsets.UTF_8), "HMAC-MD5", "");

		Assert.assertTrue(result.equals("l4MY6Yosjo7W60VJeXB/PQ=="));
	}
}
