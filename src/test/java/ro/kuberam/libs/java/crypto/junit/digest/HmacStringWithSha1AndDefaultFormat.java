package ro.kuberam.libs.java.crypto.junit.digest;

import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.libs.java.crypto.digest.Hmac;
import ro.kuberam.tests.junit.BaseTest;

public class HmacStringWithSha1AndDefaultFormat extends BaseTest {

	@Test
	public void hmacStringWithSha1() throws Exception {
		String input = "abc";
		
		String result = Hmac.hmac(input, "def", "HMAC-SHA-1");
		
		System.out.println(result);

		Assert.assertTrue(result
				.equals("dYTuFEkwcs2NmuhQ4P8JBTgjD4w="));
	}
}
