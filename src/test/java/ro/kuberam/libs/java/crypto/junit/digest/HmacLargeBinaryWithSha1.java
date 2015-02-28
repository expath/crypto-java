package ro.kuberam.libs.java.crypto.junit.digest;

import java.io.FileInputStream;

import org.apache.commons.io.IOUtils;
import ro.kuberam.libs.java.crypto.digest.Hmac;
import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class HmacLargeBinaryWithSha1 extends BaseTest {

	@Test
	public void hmacLargeBinaryWithSha1() throws Exception {
		String input = IOUtils.toString(new FileInputStream(generate5MbTempFile()));
		String secretKey = "/hWLmb8xRM75bOS6fyV9Pn0mf3Aiw+HphRCL8nOq";
		String result = Hmac.hmac(input, secretKey, "HMAC-SHA-1", "base64");
		
		System.out.println(result);

		Assert.assertTrue(result.equals("McKrpaWMrn0fzAlfw0yVDxy9esE="));
	}
}
