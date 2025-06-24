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

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.Transform;

public class Parameters {
    private String canonicalizationAlgorithm = CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS;
    private static String[] CANONICALIZATION_ALGORITHM_VALUES = {"exclusive",
            "exclusive-with-comments", "inclusive", "inclusive-with-comments"};
    private String digestAlgorithm = DigestMethod.SHA1;
    private static String[] DIGEST_ALGORITHM_VALUES = {"SHA1", "SHA256", "SHA512"};
    private String signatureAlgorithm = SignatureMethod.RSA_SHA1;
    private static String[] SIGNATURE_ALGORITHM_VALUES = {"DSA_SHA1", "RSA_SHA1"};
    private String signatureNamespacePrefix = "dsig";
    private String signatureType = "enveloped";
    private static String[] SIGNATURE_TYPE_VALUES = {"enveloping", "enveloped", "detached"};

    public String getCanonicalizationAlgorithm() {
        return canonicalizationAlgorithm;
    }

    public void setCanonicalizationAlgorithm(final String canonicalizationAlgorithm) throws CryptoException {
        if (!contains(CANONICALIZATION_ALGORITHM_VALUES, canonicalizationAlgorithm)) {
            throw new CryptoException(CryptoError.UNKNOWN_ALGORITHM);
        }

        if (canonicalizationAlgorithm.equals("exclusive")) {
            this.canonicalizationAlgorithm = CanonicalizationMethod.EXCLUSIVE;
        } else if (canonicalizationAlgorithm.equals("exclusive-with-comments")) {
            this.canonicalizationAlgorithm = CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS;
        } else if (canonicalizationAlgorithm.equals("inclusive")) {
            this.canonicalizationAlgorithm = CanonicalizationMethod.INCLUSIVE;
        }

        this.canonicalizationAlgorithm = canonicalizationAlgorithm;
    }

    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public void setDigestAlgorithm(final String digestAlgorithm) throws CryptoException {
        if (!contains(DIGEST_ALGORITHM_VALUES, digestAlgorithm)) {
            throw new CryptoException(CryptoError.UNKNOWN_ALGORITHM);
        }

        if (digestAlgorithm.equals("SHA256")) {
            this.digestAlgorithm = DigestMethod.SHA256;
        } else if (digestAlgorithm.equals("SHA512")) {
            this.digestAlgorithm = DigestMethod.SHA512;
        } else {
            this.digestAlgorithm = digestAlgorithm;
        }
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(final String signatureAlgorithm) throws CryptoException {
        if (!contains(SIGNATURE_ALGORITHM_VALUES, signatureAlgorithm)) {
            throw new CryptoException(CryptoError.UNKNOWN_ALGORITHM);
        }

        if (signatureAlgorithm.equals("DSA_SHA1")) {
            this.signatureAlgorithm = SignatureMethod.DSA_SHA1;
        } else {
            this.signatureAlgorithm = signatureAlgorithm;
        }
    }

    public String getSignatureNamespacePrefix() {
        return signatureNamespacePrefix;
    }

    public void setSignatureNamespacePrefix(final String signatureNamespacePrefix) {
        this.signatureNamespacePrefix = signatureNamespacePrefix;
    }

    public String getSignatureType() {
        System.out.println("signatureType = " + Transform.ENVELOPED);
        return signatureType;
    }

    public void setSignatureType(final String signatureType) {
        for (String e : SIGNATURE_TYPE_VALUES) {
            System.out.println("SIGNATURE_TYPE_VALUES = " + e);
        }


        if (!SIGNATURE_TYPE_VALUES.equals(signatureType)) {
            //throw new Exception(ErrorMessages.error_signatureType);
        }

        this.signatureType = signatureType;
    }

    private boolean contains(final String[] strs, final String str) {
        for (final String s : strs) {
            if (s.equals(str)) {
                return true;
            }
        }

        return false;
    }

}
