package ro.kuberam.libs.java.crypto.junit.digitalSignature;

import java.io.InputStream;

import org.apache.commons.io.IOUtils;
import ro.kuberam.libs.java.crypto.digitalSignature.GenerateXmlSignature;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;

import ro.kuberam.tests.junit.BaseTest;

public class GenerateEnvelopedDigitalSignature extends BaseTest {

	@Test
	public void generateEnvelopedDigitalSignature() throws Exception {
		InputStream inputIs = getClass().getResourceAsStream("../../doc-1.xml");
		Document input = parseXmlString(IOUtils.toString(inputIs));
		String[] certificateDetails = new String[5];
		certificateDetails[0] = "";		
		String signatureString = GenerateXmlSignature.generate(input, "inclusive", "SHA1", "DSA_SHA1", "dsig", "enveloped", null, certificateDetails, null);

		Assert.assertTrue(signatureString.contains("/KaCzo4Syrom78z3EQ5SbbB4sF7ey80etKII864WF64B81uRpH5t9jQTxeEu0ImbzRMqzVDZkVG9\nxD7nN1kuFw=="));
	}
}
