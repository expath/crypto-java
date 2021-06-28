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

import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import ro.kuberam.libs.java.crypto.CryptoException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class HMACStringTest {

    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                { "hmac-md5-default",        "HMAC-MD5",        null,       "itnbgVvBCBqOareTyzTz0w==" },
                { "hmac-md5-base64",         "HMAC-MD5",        "base64",   "itnbgVvBCBqOareTyzTz0w==" },
                { "hmac-md5-hex",            "HMAC-MD5",        "hex",      "8ad9db815bc1081a8e6ab793cb34f3d3" },
                { "hmac-sha1-default",       "HMAC-SHA-1",      null,       "nUXjFZOV3d/7v+s4dTrbEqTzld8=" },
                { "hmac-sha1-base64",        "HMAC-SHA-1",      "base64",   "nUXjFZOV3d/7v+s4dTrbEqTzld8=" },
                { "hmac-sha1-hex",           "HMAC-SHA-1",      "hex",      "9d45e3159395dddffbbfeb38753adb12a4f395df" },
                { "hmac-sha256-default",     "HMAC-SHA-256",    null,       "YhJ2cHr8vmIXeS5AwVLq921i1lAZ1MyjTReC/ek8Yaw=" },
                { "hmac-sha256-base64",      "HMAC-SHA-256",    "base64",   "YhJ2cHr8vmIXeS5AwVLq921i1lAZ1MyjTReC/ek8Yaw=" },
                { "hmac-sha256-hex",         "HMAC-SHA-256",    "hex",      "621276707afcbe6217792e40c152eaf76d62d65019d4cca34d1782fde93c61ac" },
                { "hmac-sha384-default",     "HMAC-SHA-384",    null,       "I89ANhNIxCc44IsbpfT+v9bClNTat7zlG3NWNy95M4X+1KYF6Njadcpzyocqsbik" },
                { "hmac-sha384-base64",      "HMAC-SHA-384",    "base64",   "I89ANhNIxCc44IsbpfT+v9bClNTat7zlG3NWNy95M4X+1KYF6Njadcpzyocqsbik" },
                { "hmac-sha384-hex",         "HMAC-SHA-384",    "hex",      "23cf40361348c42738e08b1ba5f4febfd6c294d4dab7bce51b7356372f793385fed4a605e8d8da75ca73ca872ab1b8a4" },
                { "hmac-sha512-default",     "HMAC-SHA-512",    null,       "pI/CNSAbX55+U5gYPSe+mGYr1dbvnBM10Kmd6VIGANGKXPA73UuL8JcX0CcESqke9n4PJLgZulaEyJvb/zx6NA==" },
                { "hmac-sha512-base64",      "HMAC-SHA-512",    "base64",   "pI/CNSAbX55+U5gYPSe+mGYr1dbvnBM10Kmd6VIGANGKXPA73UuL8JcX0CcESqke9n4PJLgZulaEyJvb/zx6NA==" },
                { "hmac-sha512-hex",         "HMAC-SHA-512",    "hex",      "a48fc235201b5f9e7e5398183d27be98662bd5d6ef9c1335d0a99de9520600d18a5cf03bdd4b8bf09717d027044aa91ef67e0f24b819ba5684c89bdbff3c7a34" },
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

    @Test
    public void hmacString() throws IOException, CryptoException {
        final String input = "Short string for tests.";
        try (final InputStream secretKeyIs = getClass().getResourceAsStream("../rsa-private-key.key")) {

            final String result = Hmac.hmac(input.getBytes(StandardCharsets.UTF_8), IOUtils.toByteArray(secretKeyIs),
                    algorithm, format);
            assertEquals(expected, result);
        }
    }

    @Test
    public void hmacString_inputStream() throws IOException, CryptoException {
        final String input = "Short string for tests.";
        try (final InputStream is = new ByteArrayInputStream(input.getBytes(UTF_8));
             final InputStream secretKeyIs = getClass().getResourceAsStream("../rsa-private-key.key")) {
            final String result = Hmac.hmac(is, IOUtils.toByteArray(secretKeyIs),
                    algorithm, format);
            assertEquals(expected, result);
        }
    }
}
