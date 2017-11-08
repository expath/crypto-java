/**
 * EXPath Cryptographic Module
 * Java Library providing an EXPath Cryptographic Module
 * Copyright (C) 2015 Kuberam
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
package ro.kuberam.libs.java.crypto.certificates;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class ValidateCertificate {

    private static final String CERT_DIR = "/data/certs/";

    public static void main(final String[] args) throws Exception {
        final ValidateCertificate verifyCertificate = new ValidateCertificate();
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
    private void verifySignature(final X509Certificate issuer, final X509Certificate cert)
            throws Exception {

        final PublicKey verifyingKey = issuer.getPublicKey();

		/*
		 * Verify the signature on the certificate using the public key. This
		 * method returns void on successful validation and in case of of a
		 * failure in verification, it throws a Signature Exception.
		 */
        cert.verify(verifyingKey);
    }

}
