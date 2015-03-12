package ro.kuberam.libs.java.crypto;

import org.junit.Assert;
import org.junit.Test;

public class ParametersTest {

	@Test
	public void testCanonicalizationAlgorithmWrongValue() {
		Parameters parameters = new Parameters();

		try {
			parameters.setCanonicalizationAlgorithm("inclusive-with-commentss");
			Assert.assertTrue(false);
		} catch (Exception e) {
			Assert.assertTrue(e.getLocalizedMessage().contains(ErrorMessages.error_unknownAlgorithm));
		}
	}

	@Test
	public void testCanonicalizationAlgorithmDefaultValue() {
		Parameters parameters = new Parameters();

		Assert.assertTrue(parameters.getCanonicalizationAlgorithm().equals(
				"inclusive-with-comments"));
	}

	@Test
	public void testDigestAlgorithmWrongValue() {
		Parameters parameters = new Parameters();

		try {
			parameters.setDigestAlgorithm("SHA1008");
			Assert.assertTrue(false);
		} catch (Exception e) {
			Assert.assertTrue(e.getLocalizedMessage().contains(ErrorMessages.error_unknownAlgorithm));
		}
	}

	@Test
	public void testDigestAlgorithmDefaultValue() {
		Parameters parameters = new Parameters();

		Assert.assertTrue(parameters.getDigestAlgorithm().equals("SHA1"));
	}

	@Test
	public void testSignatureAlgorithmWrongValue() {
		Parameters parameters = new Parameters();

		try {
			parameters.setSignatureAlgorithm("RSA_SHA1008");
			Assert.assertTrue(false);
		} catch (Exception e) {
			Assert.assertTrue(e.getLocalizedMessage().contains(ErrorMessages.error_unknownAlgorithm));
		}
	}

	@Test
	public void testSignatureAlgorithmDefaultValue() {
		Parameters parameters = new Parameters();

		Assert.assertTrue(parameters.getSignatureAlgorithm().equals("RSA_SHA1"));
	}
	
	@Test
	public void testSignatureNamespacePrefixDefaultValue() {
		Parameters parameters = new Parameters();

		Assert.assertTrue(parameters.getSignatureNamespacePrefix().equals("dsig"));
	}

}
