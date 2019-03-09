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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static ro.kuberam.libs.java.crypto.TestUtils.generate5MbFile;

@RunWith(Parameterized.class)
public class HashLargeBinaryTest {

    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                { "md5-default",        "md5",      null,       "K1yRrTmUCeybQJtm9bsA+w==" },
                { "md5-base64",         "md5",      "base64",   "K1yRrTmUCeybQJtm9bsA+w==" },
                { "md5-hex",            "md5",      "hex",      "2b5c91ad399409ec9b409b66f5bb00fb" },
                { "sha1-default",       "sha1",     null,       "uAQkoKGLYGLI6SzhFfnCduRQ+kc=" },
                { "sha1-base64",        "sha1",     "base64",   "uAQkoKGLYGLI6SzhFfnCduRQ+kc=" },
                { "sha1-hex",           "sha1",     "hex",      "b80424a0a18b6062c8e92ce115f9c276e450fa47" },
                { "sha256-default",     "sha-256",  null,       "w+00W+EpLUqgksmRJxzbaqfG43PQi1ZsG/3nQrJLFy0=" },
                { "sha256-base64",      "sha-256",  "base64",   "w+00W+EpLUqgksmRJxzbaqfG43PQi1ZsG/3nQrJLFy0=" },
                { "sha256-hex",         "sha-256",  "hex",      "c3ed345be1292d4aa092c991271cdb6aa7c6e373d08b566c1bfde742b24b172d" },
                { "sha384-default",     "sha-384",  null,       "Z6eOj8Es6VhSN4dRCBESe+6V7AhdBAU+VKbrrCqN8CDa/erGPrzvntL4J+FFQqw7" },
                { "sha384-base64",      "sha-384",  "base64",   "Z6eOj8Es6VhSN4dRCBESe+6V7AhdBAU+VKbrrCqN8CDa/erGPrzvntL4J+FFQqw7" },
                { "sha384-hex",         "sha-384",  "hex",      "67a78e8fc12ce958523787510811127bee95ec085d04053e54a6ebac2a8df020dafdeac63ebcef9ed2f827e14542ac3b" },
                { "sha512-default",     "sha-512",  null,       "ZbG4+jqkEy7SFY5/6+nAhpZ3ShwxM4YPtrcOXTspD0HOOnlH8Dx0Us1gKgMVzAjhb/0kcLVapvBq9A58PjBT+w==" },
                { "sha512-base64",      "sha-512",  "base64",   "ZbG4+jqkEy7SFY5/6+nAhpZ3ShwxM4YPtrcOXTspD0HOOnlH8Dx0Us1gKgMVzAjhb/0kcLVapvBq9A58PjBT+w==" },
                { "sha512-hex",         "sha-512",  "hex",      "65b1b8fa3aa4132ed2158e7febe9c08696774a1c3133860fb6b70e5d3b290f41ce3a7947f03c7452cd602a0315cc08e16ffd2470b55aa6f06af40e7c3e3053fb" },
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
        largeFile = generate5MbFile(temporaryFolder.newFile("hashLargeBinary"));
    }

    @Test
    public void hashLargeBinary() throws IOException, CryptoException {
        try (final InputStream is = Files.newInputStream(largeFile)) {
            final String result = Hash.hashBinary(is, algorithm, null, format);
            assertEquals(expected, result);
        }
    }
}
