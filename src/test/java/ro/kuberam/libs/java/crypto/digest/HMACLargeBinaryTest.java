/*
 * EXPath Cryptographic Module
 * Java Library providing an EXPath Cryptographic Module
 * Copyright (C) 2015 The EXPath Project
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

import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import ro.kuberam.libs.java.crypto.CryptoException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static ro.kuberam.libs.java.crypto.TestUtils.generate5MbFile;
import static ro.kuberam.libs.java.crypto.TestUtils.generate5MbString;

@RunWith(Parameterized.class)
public class HMACLargeBinaryTest {

    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                { "hmac-md5-default",        "HMAC-MD5",        null,       "YOIFbIFlb9lfrwpzoF8lzw==" },
                { "hmac-md5-base64",         "HMAC-MD5",        "base64",   "YOIFbIFlb9lfrwpzoF8lzw==" },
                { "hmac-md5-hex",            "HMAC-MD5",        "hex",      "60e2056c81656fd95faf0a73a05f25cf" },
                { "hmac-sha1-default",       "HMAC-SHA-1",      null,       "5oQ7eaxyCwKP6utsj9kngm0sj90=" },
                { "hmac-sha1-base64",        "HMAC-SHA-1",      "base64",   "5oQ7eaxyCwKP6utsj9kngm0sj90=" },
                { "hmac-sha1-hex",           "HMAC-SHA-1",      "hex",      "e6843b79ac720b028feaeb6c8fd927826d2c8fdd" },
                { "hmac-sha256-default",     "HMAC-SHA-256",    null,       "bouSmXr9knkcpCWsWLhVVjEqq/TZOWJmam+gvf9LPFk=" },
                { "hmac-sha256-base64",      "HMAC-SHA-256",    "base64",   "bouSmXr9knkcpCWsWLhVVjEqq/TZOWJmam+gvf9LPFk=" },
                { "hmac-sha256-hex",         "HMAC-SHA-256",    "hex",      "6e8b92997afd92791ca425ac58b85556312aabf4d93962666a6fa0bdff4b3c59" },
                { "hmac-sha384-default",     "HMAC-SHA-384",    null,       "BBzLFaQammdp4BlanF/TKnIXt1mW56vz3imLcGOGNLRf6khRF8nsseQKpvt6W4Cx" },
                { "hmac-sha384-base64",      "HMAC-SHA-384",    "base64",   "BBzLFaQammdp4BlanF/TKnIXt1mW56vz3imLcGOGNLRf6khRF8nsseQKpvt6W4Cx" },
                { "hmac-sha384-hex",         "HMAC-SHA-384",    "hex",      "041ccb15a41a9a6769e0195a9c5fd32a7217b75996e7abf3de298b70638634b45fea485117c9ecb1e40aa6fb7a5b80b1" },
                { "hmac-sha512-default",     "HMAC-SHA-512",    null,       "qE1L1nxv9vY6elfkfCaZEOXD1M8lYZ0FhA0h0tMZ56Ec769enwam/RCJ3kfkJRP1TWglMSgwyquSd68pO9SAJg==" },
                { "hmac-sha512-base64",      "HMAC-SHA-512",    "base64",   "qE1L1nxv9vY6elfkfCaZEOXD1M8lYZ0FhA0h0tMZ56Ec769enwam/RCJ3kfkJRP1TWglMSgwyquSd68pO9SAJg==" },
                { "hmac-sha512-hex",         "HMAC-SHA-512",    "hex",      "a84d4bd67c6ff6f63a7a57e47c269910e5c3d4cf25619d05840d21d2d319e7a11cefaf5e9f06a6fd1089de47e42513f54d6825312830caab9277af293bd48026" },
        });
    }

    @Parameterized.Parameter
    public String testTypeName;

    @Parameterized.Parameter(value = 1)
    public String algorithm;

    @Parameterized.Parameter(value = 2)
    public String format;

    @Parameterized.Parameter(value = 3)
    public String expected;

    @ClassRule
    public static final TemporaryFolder temporaryFolder = new TemporaryFolder();

    private static Path largeFile;

    @BeforeClass
    public static void setup() throws IOException {
        largeFile = generate5MbFile(temporaryFolder.newFile("hmacLargeBinary"));
    }

    @Test
    public void hmacLargeBinary_inputStream() throws IOException, CryptoException {
        try(final InputStream is = Files.newInputStream(largeFile)) {
            final String secretKey = "/hWLmb8xRM75bOS6fyV9Pn0mf3Aiw+HphRCL8nOq";
            final String result = Hmac.hmac(is,
                    secretKey.getBytes(UTF_8), algorithm, format);

            assertEquals(expected, result);
        }
    }
}
