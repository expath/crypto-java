package ro.kuberam.libs.java.crypto.digest;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class HmacStringWithSha256 extends BaseTest {

	@Test
	public void hmacStringWithSha256() throws Exception {
		String input = "20120215";

		String result = Hmac.hmac(input.getBytes(StandardCharsets.UTF_8),
				"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".getBytes(StandardCharsets.UTF_8),
				"HMAC-SHA-256", "base64");
		System.out.println(result);

		result = Hmac.hmac("us-east-1".getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(result), "HMAC-SHA-256", "base64");
		System.out.println(result);

		result = Hmac.hmac("iam".getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(result), "HMAC-SHA-256", "base64");
		System.out.println(result);

		result = Hmac.hmac("aws4_request".getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(result), "HMAC-SHA-256", "hex");
		System.out.println(result);

		Assert.assertTrue(result.equals("f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"));
	}
}
