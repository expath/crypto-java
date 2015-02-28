package ro.kuberam.libs.java.crypto.junit.digitalSignature;

import java.io.InputStream;

import org.apache.commons.io.IOUtils;
import ro.kuberam.libs.java.crypto.digitalSignature.GenerateXmlSignature;
import ro.kuberam.libs.java.crypto.digitalSignature.ValidateXmlSignature;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;

import ro.kuberam.tests.junit.BaseTest;

public class ValidateEnvelopedDigitalSignature extends BaseTest {

	@Test
	public void test() throws Exception {
		InputStream inputIs = getClass().getResourceAsStream("../../doc-1.xml");
		Document input = parseXmlString(IOUtils.toString(inputIs));
		String[] certificateDetails = new String[5];
		certificateDetails[0] = "";		
		String signatureString = GenerateXmlSignature.generate(input, "inclusive", "SHA1", "DSA_SHA1", "dsig", "enveloped", null, certificateDetails, null);
		Document signature = parseXmlString(signatureString);
		boolean validateSignature = ValidateXmlSignature.validate(signature);
		Assert.assertTrue(validateSignature);
	}
}
