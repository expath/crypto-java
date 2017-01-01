package ro.kuberam.libs.java.crypto.digest;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;

import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class GenerateAWSsignature extends BaseTest {

	@Test
	public void hmacStringWithSha256() throws Exception {
		String key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
		String dateStamp = "20120215";
		String regionName = "us-east-1";
		String serviceName = "iam";

		String kSecret = "AWS4" + key;
		String kSecretHexValue = DatatypeConverter.printHexBinary(kSecret.getBytes(StandardCharsets.UTF_8))
				.toLowerCase();
		Assert.assertTrue(kSecretHexValue
				.equals("41575334774a616c725855746e46454d492f4b374d44454e472b62507852666943594558414d504c454b4559"));

		byte[] kDate = Hmac.hmac(dateStamp.getBytes(StandardCharsets.UTF_8), kSecret.getBytes(StandardCharsets.UTF_8),
				"HMAC-SHA-256");
		System.out.println(Arrays.toString(kDate));
		String kDateHexValue = generateHexValue(kDate);
		Assert.assertTrue(kDateHexValue.equals("969fbb94feb542b71ede6f87fe4d5fa29c789342b0f407474670f0c2489e0a0d"));

		byte[] kRegion = Hmac.hmac(regionName.getBytes(StandardCharsets.UTF_8), kDate, "HMAC-SHA-256");
		String kRegionHexValue = generateHexValue(kRegion);
		Assert.assertTrue(kRegionHexValue.equals("69daa0209cd9c5ff5c8ced464a696fd4252e981430b10e3d3fd8e2f197d7a70c"));

		byte[] kService = Hmac.hmac(serviceName.getBytes(StandardCharsets.UTF_8), kRegion, "HMAC-SHA-256");
		String kServiceHexValue = generateHexValue(kService);
		Assert.assertTrue(kServiceHexValue.equals("f72cfd46f26bc4643f06a11eabb6c0ba18780c19a8da0c31ace671265e3c87fa"));

		byte[] kSigning = Hmac.hmac("aws4_request".getBytes(StandardCharsets.UTF_8), kService, "HMAC-SHA-256");
		String kSigningHexValue = generateHexValue(kSigning);
		Assert.assertTrue(kSigningHexValue.equals("f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"));
	}

	private String generateHexValue(byte[] hexValue) {
		return DatatypeConverter.printHexBinary(hexValue).toLowerCase();
	}
}
