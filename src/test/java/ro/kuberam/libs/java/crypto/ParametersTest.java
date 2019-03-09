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

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class ParametersTest {

    @Test
    public void testCanonicalizationAlgorithmWrongValue() {
        final Parameters parameters = new Parameters();

        try {
            parameters.setCanonicalizationAlgorithm("inclusive-with-commentss");
            fail("Algorithm should have been unknown");
        } catch (CryptoException e) {
            assertEquals(CryptoError.UNKNOWN_ALGORITHM, e.getCryptoError());
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
            fail("Algorithm should have been unknown");
        } catch (CryptoException e) {
            assertEquals(CryptoError.UNKNOWN_ALGORITHM, e.getCryptoError());
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
            fail("Algorithm should have been unknown");
        } catch (CryptoException e) {
            assertEquals(CryptoError.UNKNOWN_ALGORITHM, e.getCryptoError());
        }
    }

    @Test
    public void testSignatureAlgorithmDefaultValue() {
        final Parameters parameters = new Parameters();
        assertEquals("http://www.w3.org/2000/09/xmldsig#rsa-sha1", parameters.getSignatureAlgorithm());
    }

    @Test
    public void testSignatureNamespacePrefixDefaultValue() {
        final Parameters parameters = new Parameters();
        assertEquals("dsig", parameters.getSignatureNamespacePrefix());
    }
}
