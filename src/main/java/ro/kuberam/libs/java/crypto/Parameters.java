package ro.kuberam.libs.java.crypto;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.Transform;

public class Parameters {
	private String canonicalizationAlgorithm = CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS;
	private String[] canonicalizationAlgorithmValues = new String[] { "exclusive",
			"exclusive-with-comments", "inclusive", "inclusive-with-comments" };
	private String digestAlgorithm = DigestMethod.SHA1;
	private String[] digestAlgorithmValues = new String[] { "SHA1", "SHA256", "SHA512" };
	private String signatureAlgorithm = SignatureMethod.RSA_SHA1;
	private String[] signatureAlgorithmValues = new String[] { "DSA_SHA1", "RSA_SHA1" };
	private String signatureNamespacePrefix = "dsig";
	private String signatureType = "enveloped";
	private String[] signatureTypeValues = new String[] { "enveloping", "enveloped", "detached" };

	public Parameters() {
	}

	public String getCanonicalizationAlgorithm() {
		return canonicalizationAlgorithm;
	}

	public void setCanonicalizationAlgorithm(String canonicalizationAlgorithm) throws Exception {
		if (!canonicalizationAlgorithmValues.equals(canonicalizationAlgorithm)) {
			throw new Exception(ErrorMessages.error_unknownAlgorithm);
		}

		if (canonicalizationAlgorithm.equals("exclusive")) {
			canonicalizationAlgorithm = CanonicalizationMethod.EXCLUSIVE;
		} else if (canonicalizationAlgorithm.equals("exclusive-with-comments")) {
			canonicalizationAlgorithm = CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS;
		} else if (canonicalizationAlgorithm.equals("inclusive")) {
			canonicalizationAlgorithm = CanonicalizationMethod.INCLUSIVE;
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

		if (digestAlgorithm.equals("SHA256")) {
			digestAlgorithm = DigestMethod.SHA256;
		} else if (digestAlgorithm.equals("SHA512")) {
			digestAlgorithm = DigestMethod.SHA512;
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

		if (signatureAlgorithm.equals("DSA_SHA1")) {
			signatureAlgorithm = SignatureMethod.DSA_SHA1;
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
		System.out.println("signatureType = " + Transform.ENVELOPED);
		return signatureType;
	}

	public void setSignatureType(String signatureType) throws Exception {
		for (String e : signatureTypeValues) {
			System.out.println("signatureTypeValues = " + e);	
		}
			
		
		if (!signatureTypeValues.equals(signatureType)) {
			//throw new Exception(ErrorMessages.error_signatureType);
		}

		this.signatureType = signatureType;
	}

}
