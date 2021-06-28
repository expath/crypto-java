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
package ro.kuberam.libs.java.crypto.digest;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertEquals;

public class GenerateAWSSignatureTest extends BaseTest {

    @Test
    public void hmacStringWithSha256() throws Exception {
        final String key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        final String dateStamp = "20120215";
        final String regionName = "us-east-1";
        final String serviceName = "iam";

        final String kSecret = "AWS4" + key;
        final String kSecretHexValue = DatatypeConverter.printHexBinary(kSecret.getBytes(StandardCharsets.UTF_8))
                .toLowerCase();
        assertEquals("41575334774a616c725855746e46454d492f4b374d44454e472b62507852666943594558414d504c454b4559", kSecretHexValue);

        final byte[] kDate = Hmac.hmac(dateStamp.getBytes(StandardCharsets.UTF_8), kSecret.getBytes(StandardCharsets.UTF_8),
                "HMAC-SHA-256");
        System.out.println(Arrays.toString(kDate));
        final String kDateHexValue = generateHexValue(kDate);
        assertEquals("969fbb94feb542b71ede6f87fe4d5fa29c789342b0f407474670f0c2489e0a0d", kDateHexValue);

        final byte[] kRegion = Hmac.hmac(regionName.getBytes(StandardCharsets.UTF_8), kDate, "HMAC-SHA-256");
        String kRegionHexValue = generateHexValue(kRegion);
        assertEquals("69daa0209cd9c5ff5c8ced464a696fd4252e981430b10e3d3fd8e2f197d7a70c", kRegionHexValue);

        final byte[] kService = Hmac.hmac(serviceName.getBytes(StandardCharsets.UTF_8), kRegion, "HMAC-SHA-256");
        String kServiceHexValue = generateHexValue(kService);
        assertEquals("f72cfd46f26bc4643f06a11eabb6c0ba18780c19a8da0c31ace671265e3c87fa", kServiceHexValue);

        final byte[] kSigning = Hmac.hmac("aws4_request".getBytes(StandardCharsets.UTF_8), kService, "HMAC-SHA-256");
        String kSigningHexValue = generateHexValue(kSigning);
        assertEquals("f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d", kSigningHexValue);
    }

    private String generateHexValue(byte[] hexValue) {
        return DatatypeConverter.printHexBinary(hexValue).toLowerCase();
    }
}
