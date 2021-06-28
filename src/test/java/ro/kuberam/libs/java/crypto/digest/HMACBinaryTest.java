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
import static org.junit.Assert.assertNotNull;

@RunWith(Parameterized.class)
public class HMACBinaryTest {

    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                { "hmac-md5-default",        "HMAC-MD5",        null,       "qos0Wi3v2UmUINvZxUjlfw==" },
                { "hmac-md5-base64",         "HMAC-MD5",        "base64",   "qos0Wi3v2UmUINvZxUjlfw==" },
                { "hmac-md5-hex",            "HMAC-MD5",        "hex",      "aa8b345a2defd9499420dbd9c548e57f" },
                { "hmac-sha1-default",       "HMAC-SHA-1",      null,       "PQ35fW3zSlpw5l9t+dlc4Uuw4yw=" },
                { "hmac-sha1-base64",        "HMAC-SHA-1",      "base64",   "PQ35fW3zSlpw5l9t+dlc4Uuw4yw=" },
                { "hmac-sha1-hex",           "HMAC-SHA-1",      "hex",      "3d0df97d6df34a5a70e65f6df9d95ce14bb0e32c" },
                { "hmac-sha256-default",     "HMAC-SHA-256",    null,       "B+4Sajr34uDevILQascNd7wWh7hl/rSIHmXFbzmkxs0=" },
                { "hmac-sha256-base64",      "HMAC-SHA-256",    "base64",   "B+4Sajr34uDevILQascNd7wWh7hl/rSIHmXFbzmkxs0=" },
                { "hmac-sha256-hex",         "HMAC-SHA-256",    "hex",      "07ee126a3af7e2e0debc82d06ac70d77bc1687b865feb4881e65c56f39a4c6cd" },
                { "hmac-sha384-default",     "HMAC-SHA-384",    null,       "M2ZLLFCj2z+lUTtYFkjpKCIFVrCW+Z6rm369t2CF5rQJfiQM8BeXskpl/mRvwLiR" },
                { "hmac-sha384-base64",      "HMAC-SHA-384",    "base64",   "M2ZLLFCj2z+lUTtYFkjpKCIFVrCW+Z6rm369t2CF5rQJfiQM8BeXskpl/mRvwLiR" },
                { "hmac-sha384-hex",         "HMAC-SHA-384",    "hex",      "33664b2c50a3db3fa5513b581648e928220556b096f99eab9b7ebdb76085e6b4097e240cf01797b24a65fe646fc0b891" },
                { "hmac-sha512-default",     "HMAC-SHA-512",    null,       "m4wf0sXN0CUH4LuTWnrz+OlF3y2O4TPY1grp8Z3JKK+jzu340L1+UBVV3dSiKa/phSTb97FBpCjwQTBKbAs8Cw==" },
                { "hmac-sha512-base64",      "HMAC-SHA-512",    "base64",   "m4wf0sXN0CUH4LuTWnrz+OlF3y2O4TPY1grp8Z3JKK+jzu340L1+UBVV3dSiKa/phSTb97FBpCjwQTBKbAs8Cw==" },
                { "hmac-sha512-hex",         "HMAC-SHA-512",    "hex",      "9b8c1fd2c5cdd02507e0bb935a7af3f8e945df2d8ee133d8d60ae9f19dc928afa3ceedf8d0bd7e501555ddd4a229afe98524dbf7b141a428f041304a6c0b3c0b" },
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
    public void hmacBinary() throws IOException, CryptoException {
        try (final InputStream input = getClass().getResourceAsStream("../keystore.ks");
             final InputStream secretKeyIs = getClass().getResourceAsStream("../rsa-private-key.key")) {
            assertNotNull(input);

            final String result = Hmac.hmac(input, IOUtils.toByteArray(secretKeyIs),
                    algorithm, format);
            assertEquals(expected, result);
        }
    }
}
