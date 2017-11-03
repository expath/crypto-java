package ro.kuberam.libs.java.crypto.digitalSignature;

import java.io.InputStream;

import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.w3c.dom.Document;

import ro.kuberam.tests.junit.BaseTest;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertTrue;

public class ValidateEnvelopedDigitalSignature extends BaseTest {

    @Test
    public void test() throws Exception {
        try (final InputStream inputIs = getClass().getResourceAsStream("../doc-1.xml")) {
            final Document input = parseXmlString(IOUtils.toString(inputIs, UTF_8));
            final String[] certificateDetails = new String[5];
            certificateDetails[0] = "";
            final String signatureString = GenerateXmlSignature.generate(input, "inclusive", "SHA1", "DSA_SHA1", "dsig", "enveloped", null, certificateDetails, null);
            final Document signature = parseXmlString(signatureString);
            final boolean validateSignature = ValidateXmlSignature.validate(signature);
            assertTrue(validateSignature);
        }
    }
}
