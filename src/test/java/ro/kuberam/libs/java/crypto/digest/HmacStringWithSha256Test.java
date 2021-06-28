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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertTrue;

public class HmacStringWithSha256Test extends BaseTest {

    @Test
    public void hmacStringWithSha256() throws Exception {
        final String input = "20120215";
        try (final InputStream is = new ByteArrayInputStream(input.getBytes(UTF_8))) {
            String result = Hmac.hmac(is,
                    "AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".getBytes(StandardCharsets.UTF_8),
                    "HMAC-SHA-256", "base64");
            System.out.println(result);

            result = Hmac.hmac("us-east-1".getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(result), "HMAC-SHA-256", "base64");
            System.out.println(result);

            result = Hmac.hmac("iam".getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(result), "HMAC-SHA-256", "base64");
            System.out.println(result);

            result = Hmac.hmac("aws4_request".getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(result), "HMAC-SHA-256", "hex");
            System.out.println(result);

            assertTrue(result.equals("f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"));
        }
    }

    @Test
    public void hmacStringWithSha256_inputStream() throws Exception {
        final String input = "20120215";
        String result = Hmac.hmac(input.getBytes(UTF_8),
                "AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".getBytes(StandardCharsets.UTF_8),
                "HMAC-SHA-256", "base64");
        System.out.println(result);

        result = Hmac.hmac("us-east-1".getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(result), "HMAC-SHA-256", "base64");
        System.out.println(result);

        result = Hmac.hmac("iam".getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(result), "HMAC-SHA-256", "base64");
        System.out.println(result);

        result = Hmac.hmac("aws4_request".getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(result), "HMAC-SHA-256", "hex");
        System.out.println(result);

        assertTrue(result.equals("f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"));
    }
}
