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
package ro.kuberam.libs.java.crypto.digitalSignature;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;

import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.w3c.dom.Document;

import ro.kuberam.tests.junit.BaseTest;

public class GenerateEnvelopedDigitalSignature extends BaseTest {

    @Test
    public void generateEnvelopedDigitalSignature() throws Exception {
        try (final InputStream inputIs = getClass().getResourceAsStream("../doc-1.xml")) {
            final Document input = parseXmlString(IOUtils.toString(inputIs, UTF_8));
            final String[] certificateDetails = new String[5];
            certificateDetails[0] = "";
            final String signatureString = GenerateXmlSignature.generate(input, "inclusive", "SHA1", "DSA_SHA1", "dsig", "enveloped", null, certificateDetails, null);

            assertTrue(signatureString.contains("/KaCzo4Syrom78z3EQ5SbbB4sF7ey80etKII864WF64B81uRpH5t9jQTxeEu0ImbzRMqzVDZkVG9\nxD7nN1kuFw=="));
        }
    }
}
