package ro.kuberam.libs.java.crypto;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ParametersTest {

    @Test
    public void testCanonicalizationAlgorithmWrongValue() {
        final Parameters parameters = new Parameters();

        try {
            parameters.setCanonicalizationAlgorithm("inclusive-with-commentss");
            assertTrue(false);
        } catch (final Exception e) {
            assertTrue(e.getLocalizedMessage().contains(ErrorMessages.error_unknownAlgorithm));
        }
    }

    @Test
    public void testCanonicalizationAlgorithmDefaultValue() {
        final Parameters parameters = new Parameters();
        assertEquals("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments", parameters.getCanonicalizationAlgorithm());
    }

    @Test
    public void testDigestAlgorithmWrongValue() {
        final Parameters parameters = new Parameters();

        try {
            parameters.setDigestAlgorithm("SHA1008");
            assertTrue(false);
        } catch (final Exception e) {
            assertTrue(e.getLocalizedMessage().contains(ErrorMessages.error_unknownAlgorithm));
        }
    }

    @Test
    public void testDigestAlgorithmDefaultValue() {
        final Parameters parameters = new Parameters();

        assertEquals("http://www.w3.org/2000/09/xmldsig#sha1", parameters.getDigestAlgorithm());
    }

    @Test
    public void testSignatureAlgorithmWrongValue() {
        final Parameters parameters = new Parameters();

        try {
            parameters.setSignatureAlgorithm("RSA_SHA1008");
            assertTrue(false);
        } catch (final Exception e) {
            assertTrue(e.getLocalizedMessage().contains(ErrorMessages.error_unknownAlgorithm));
        }
    }

    @Test
    public void testSignatureAlgorithmDefaultValue() {
        final Parameters parameters = new Parameters();
        System.out.println(parameters.getSignatureAlgorithm());
        assertEquals("http://www.w3.org/2000/09/xmldsig#rsa-sha1", parameters.getSignatureAlgorithm());
    }

    @Test
    public void testSignatureNamespacePrefixDefaultValue() {
        final Parameters parameters = new Parameters();

        assertEquals("dsig", parameters.getSignatureNamespacePrefix());
    }

}
