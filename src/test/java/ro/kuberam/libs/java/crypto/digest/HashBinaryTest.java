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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import ro.kuberam.libs.java.crypto.CryptoException;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@RunWith(Parameterized.class)
public class HashBinaryTest {

    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                { "md5-default",        "md5",      null,       "UI/aOJodA6gtJPitQ6xcJA==" },
                { "md5-base64",         "md5",      "base64",   "UI/aOJodA6gtJPitQ6xcJA==" },
                { "md5-hex",            "md5",      "hex",      "508fda389a1d03a82d24f8ad43ac5c24" },
                { "sha1-default",       "sha1",     null,       "GyscHvnJKxInsBLgSg/FRAmQXYU=" },
                { "sha1-base64",        "sha1",     "base64",   "GyscHvnJKxInsBLgSg/FRAmQXYU=" },
                { "sha1-hex",           "sha1",     "hex",      "1b2b1c1ef9c92b1227b012e04a0fc54409905d85" },
                { "sha256-default",     "sha-256",  null,       "37JiNBym250ye3aUJ04RaZg3SFSP03qJ8FR/I1JckVI=" },
                { "sha256-base64",      "sha-256",  "base64",   "37JiNBym250ye3aUJ04RaZg3SFSP03qJ8FR/I1JckVI=" },
                { "sha256-hex",         "sha-256",  "hex",      "dfb262341ca6db9d327b7694274e1169983748548fd37a89f0547f23525c9152" },
                { "sha384-default",     "sha-384",  null,       "DcQ3caBftiQCIQn96Pr8PC2vzs17Re0tZ8/CZnOoucu/N+818uqAXxR7l9oxYgoW" },
                { "sha384-base64",      "sha-384",  "base64",   "DcQ3caBftiQCIQn96Pr8PC2vzs17Re0tZ8/CZnOoucu/N+818uqAXxR7l9oxYgoW" },
                { "sha384-hex",         "sha-384",  "hex",      "0dc43771a05fb624022109fde8fafc3c2dafcecd7b45ed2d67cfc26673a8b9cbbf37ef35f2ea805f147b97da31620a16" },
                { "sha512-default",     "sha-512",  null,       "Be+hlGy9TNibbaE+6DA2gu6kNj2GS+7b4egFcJDMzQSFQiGgFtTh/mD61ta4pDvc+jqHFlqOyJLHirkROd86Mw==" },
                { "sha512-base64",      "sha-512",  "base64",   "Be+hlGy9TNibbaE+6DA2gu6kNj2GS+7b4egFcJDMzQSFQiGgFtTh/mD61ta4pDvc+jqHFlqOyJLHirkROd86Mw==" },
                { "sha512-hex",         "sha-512",  "hex",      "05efa1946cbd4cd89b6da13ee8303682eea4363d864beedbe1e8057090cccd04854221a016d4e1fe60fad6d6b8a43bdcfa3a87165a8ec892c78ab91139df3a33" },
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
    public void hashBinary() throws IOException, CryptoException {
        try (final InputStream input = getClass().getResourceAsStream("../keystore.ks")) {
            assertNotNull(input);

            final String result = Hash.hashBinary(input, algorithm, null, format);
            assertEquals(expected, result);
        }
    }
}
