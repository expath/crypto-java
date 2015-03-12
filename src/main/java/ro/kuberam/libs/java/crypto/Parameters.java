package ro.kuberam.libs.java.crypto;

public class Parameters {
	private String canonicalizationAlgorithm = "inclusive-with-comments";
	private String[] canonicalizationAlgorithmValues = new String[] { "exclusive",
			"exclusive-with-comments", "inclusive", "inclusive-with-comments" };
	private String digestAlgorithm = "SHA1";
	private String[] digestAlgorithmValues = new String[] { "SHA1", "SHA256", "SHA512" };
	private String signatureAlgorithm = "RSA_SHA1";
	private String[] signatureAlgorithmValues = new String[] { "DSA_SHA1", "RSA_SHA1" };
	private String signatureNamespacePrefix = "dsig";
	private String signatureType = "enveloped";
	private String[] signatureTypeValues = new String[] { "DSA_SHA1", "RSA_SHA1" };

	public Parameters() {
	}

	public String getCanonicalizationAlgorithm() {
		return canonicalizationAlgorithm;
	}

	public void setCanonicalizationAlgorithm(String canonicalizationAlgorithm) throws Exception {
		if (!canonicalizationAlgorithmValues.equals(canonicalizationAlgorithm)) {
			throw new Exception(ErrorMessages.error_unknownAlgorithm);
		}

		this.canonicalizationAlgorithm = canonicalizationAlgorithm;
	}

	public String getDigestAlgorithm() {
		return digestAlgorithm;
	}

	public void setDigestAlgorithm(String digestAlgorithm) throws Exception {
		if (!digestAlgorithmValues.equals(digestAlgorithm)) {
			throw new Exception(ErrorMessages.error_unknownAlgorithm);
		}

		this.digestAlgorithm = digestAlgorithm;
	}

	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public void setSignatureAlgorithm(String signatureAlgorithm) throws Exception {
		if (!signatureAlgorithmValues.equals(signatureAlgorithm)) {
			throw new Exception(ErrorMessages.error_unknownAlgorithm);
		}

		this.signatureAlgorithm = signatureAlgorithm;
	}

	public String getSignatureNamespacePrefix() {
		return signatureNamespacePrefix;
	}

	public void setSignatureNamespacePrefix(String signatureNamespacePrefix) {
		this.signatureNamespacePrefix = signatureNamespacePrefix;
	}

	public String getSignatureType() {
		return signatureType;
	}

	public void setSignatureType(String signatureType) throws Exception {
		if (!signatureTypeValues.equals(signatureType)) {
			throw new Exception(ErrorMessages.error_signatureType);
		}

		this.signatureType = signatureType;
	}

}
