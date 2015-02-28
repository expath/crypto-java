package ro.kuberam.libs.java.crypto.certificates;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class ValidateCertificate {

	private static final String CERT_DIR = "/data/certs/";

	public static void main(String[] args) throws Exception {
		ValidateCertificate verifyCertificate = new ValidateCertificate();
		verifyCertificate.runSample();
	}

	public void runSample() throws Exception {


		/*
		 * Load and verify each certificate. 1. Load certificates into
		 * X509Certificate object 2. Verify each certificate using its
		 * corresponding public key of the issuer certificate.
		 */
//		X509Certificate cert = CertUtil.loadX509Certificate(CERT_DIR
//				+ "janet.crt");
//		X509Certificate issuerCA = CertUtil.loadX509Certificate(CERT_DIR
//				+ "CAphoenix.crt");
//		X509Certificate rootCA = CertUtil.loadX509Certificate(CERT_DIR
//				+ "CAseattle.crt");

//		verifySignature(rootCA, rootCA);
//		verifySignature(rootCA, issuerCA);
//		verifySignature(issuerCA, cert);
	}

	/*
	 * Verify certificate's signature.
	 * 
	 * @param issuer The X509 issuer certificate.
	 * 
	 * @param cert The X509 certificate to be verified.
	 * 
	 * @throws Exception On failure.
	 */
	private void verifySignature(X509Certificate issuer, X509Certificate cert)
			throws Exception {

		PublicKey verifyingKey = issuer.getPublicKey();

		/*
		 * Verify the signature on the certificate using the public key. This
		 * method returns void on successful validation and in case of of a
		 * failure in verification, it throws a Signature Exception.
		 */
		cert.verify(verifyingKey);
	}

}
