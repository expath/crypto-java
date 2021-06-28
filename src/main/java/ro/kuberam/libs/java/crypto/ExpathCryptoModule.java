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
package ro.kuberam.libs.java.crypto;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Implements the module definition.
 *
 * @author <a href="mailto:claudius.teodorescu@gmail.com">Claudius Teodorescu</a>
 */
public class ExpathCryptoModule {

//	static {
//		java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
//	}
//	
//	public final static Provider defaultProvider = java.security.Security.getProvider("BC");

    public static final Properties libProperties = new Properties();

    static {
        try (final InputStream propertiesIs = ExpathCryptoModule.class.getResourceAsStream("lib.properties")) {
            libProperties.load(propertiesIs);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static final String NAMESPACE_URI = "http://expath.org/ns/crypto";
    public static final String PREFIX = "crypto";
    public static final String VERSION = libProperties.getProperty("lib-version");
    public static final String MODULE_DESCRIPTION = "A module for providing cryptographic services.";
    public static final String MODULE_NAME = "EXPath Cryptographic";

    public static final Map<String, String> javaStandardAlgorithmNames = new HashMap<>();

    static {
        javaStandardAlgorithmNames.put("HMAC-MD5", "HmacMD5");
        javaStandardAlgorithmNames.put("HMAC-SHA-1", "HmacSHA1");
        javaStandardAlgorithmNames.put("HMAC-SHA-256", "HmacSHA256");
        javaStandardAlgorithmNames.put("HMAC-SHA-384", "HmacSHA384");
        javaStandardAlgorithmNames.put("HMAC-SHA-512", "HmacSHA512");
    }

    // crypto:generate-signature() description
    public static final String canonicalization_algorithm = "The canonicalization algorithm applied to the SignedInfo element prior to performing signature calculations. Possible values are: 'exclusive', 'exclusive-with-comments', 'inclusive', and 'inclusive-with-comments'. The default value is 'inclusive-with-comments'.";
    public static final String DIGEST_ALGORITHM = "The digest algorithm to be applied to the signed object. Possible values are: 'SHA1', 'SHA256', and 'SHA512'. The default value is 'SHA1'.";
    public static final String SIGNATURE_ALGORITHM = "The algorithm used for signature generation and validation. Possible values are: 'DSA_SHA1', and 'RSA_SHA1'. The default value is 'RSA_SHA1'.";
    public static final String SIGNATURE_TYPE = "The method used for signing the content of signature. Possible values are: 'enveloping', 'enveloped', and 'detached'. The default value is 'enveloped'.";
    public static final String digitalCertificateDetailsDescription = "Details about the digital certificate to be used for signing the input document or document subset."
            + " The structure of this parameter is as follows (this is an example): "
            + "<digital-certificate>"
            + "<keystore-type>JKS</keystore-type>"
            + "<keystore-password>ab987c</keystore-password>"
            + "<key-alias>eXist</key-alias>"
            + "<private-key-password>kpi135</private-key-password>"
            + "<keystore-uri>/db/mykeystoreEXist.ks</keystore-uri>" + "</digital-certificate>.";
}