package ro.kuberam.libs.java.crypto.junit.digest;

import java.io.InputStream;

import org.apache.commons.io.IOUtils;
import ro.kuberam.libs.java.crypto.digest.Hmac;
import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class HmacStringWithSha384 extends BaseTest {

	@Test
	public void hmacStringWithSha384() throws Exception {
		String input = "Short string for tests.";
		InputStream secretKeyIs = getClass().getResourceAsStream("../../private-key.pem");
		
		String result = Hmac.hmac(input, IOUtils.toString(secretKeyIs), "HMAC-SHA-384", "base64");

		Assert.assertTrue(result
				.equals("RRirKZTmx+cG8EXvgrRnpYFPEPYXaZBirY+LFmiUBAK61LCryDsL4clFRG5/BcBr"));
	}
}
