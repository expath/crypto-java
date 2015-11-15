package ro.kuberam.libs.java.crypto.digest;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class HmacStringWithSha256 extends BaseTest {

	@Test
	public void hmacStringWithSha256() throws Exception {
		String input = "20120215";
		InputStream secretKeyIs = getClass().getResourceAsStream("../rsa-private-key.key");

		String result = Hmac.hmac(input, "AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "HMAC-SHA-256",
				"base64");
		System.out.println("result = " + result);

		result = Hmac.hmac("us-east-1", result, "HMAC-SHA-256", "base64");
		System.out.println("result = " + result);

		result = Hmac.hmac("iam", result, "HMAC-SHA-256", "base64");
		System.out.println("result = " + result);

		result = Hmac.hmac("aws4_request", result, "HMAC-SHA-256", "hex");
		System.out.println("result = " + result);

		Assert.assertTrue(result.equals("f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"));

		byte[] salt = "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d".getBytes(StandardCharsets.UTF_8);
//		System.out.println("printBase64Binary " + DatatypeConverter.printBase64Binary(salt));
	}
}
