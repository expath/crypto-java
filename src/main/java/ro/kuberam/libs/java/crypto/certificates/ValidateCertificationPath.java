/*
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

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertificateException;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;

public class ValidateCertificationPath {

    public static byte[] validate(final CertPath certPath) throws Exception {

        try {
            //TODO: pay attention that this class maybe uses deprecated java.security.*

            final KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            final String password = "changeit";

            // Load the JDK's cacerts keystore file
            final Path filename = Paths.get(System.getProperty("java.home"), "lib", "security", "cacerts");

            try (final InputStream is = Files.newInputStream(filename)) {
                keystore.load(is, password.toCharArray());
            }

            // Create the parameters for the validator
            final PKIXParameters params = new PKIXParameters(keystore);

            // Disable CRL checking since we are not supplying any CRLs
            params.setRevocationEnabled(false);

            // Create the validator and validate the path
            // To create a path, see Creating a Certification Path
            final CertPathValidator certPathValidator
                    = CertPathValidator.getInstance(CertPathValidator.getDefaultType());
            final CertPathValidatorResult result = certPathValidator.validate(certPath, params);

            // Get the CA used to validate this path
            final PKIXCertPathValidatorResult pkixResult = (PKIXCertPathValidatorResult) result;
            final TrustAnchor ta = pkixResult.getTrustAnchor();
            java.security.cert.X509Certificate cert = ta.getTrustedCert();
        } catch (CertificateException | KeyStoreException | NoSuchAlgorithmException | CertPathValidatorException | InvalidAlgorithmParameterException e) {
        }
        return null;

    }

}
