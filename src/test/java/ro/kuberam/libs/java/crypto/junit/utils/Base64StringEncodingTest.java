package ro.kuberam.libs.java.crypto.junit.utils;

import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.libs.java.crypto.utils.Base64;

public class Base64StringEncodingTest {

	@Test
	public void test1() {
		String encodedString = Base64.encodeToString("id".getBytes(), true);
		System.out.println("Encoded string:\n" + encodedString);
		Assert.assertTrue(encodedString.equals("aWQ="));
	}

}
