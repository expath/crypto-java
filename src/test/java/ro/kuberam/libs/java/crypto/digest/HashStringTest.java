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
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class HashStringTest {

    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                { "md5-default",        "md5",      null,       "use1oAoe8vIgnFgygz2OKw==" },
                { "md5-base64",         "md5",      "base64",   "use1oAoe8vIgnFgygz2OKw==" },
                { "md5-hex",            "md5",      "hex",      "bac7b5a00a1ef2f2209c5832833d8e2b" },
                { "sha1-default",       "sha1",     null,       "cV2wx17vo8eH2TaFRvCIIvJjNqU=" },
                { "sha1-base64",        "sha1",     "base64",   "cV2wx17vo8eH2TaFRvCIIvJjNqU=" },
                { "sha1-hex",           "sha1",     "hex",      "715db0c75eefa3c787d9368546f08822f26336a5" },
                { "sha256-default",     "sha-256",  null,       "E+B0JzLRgxm2+1rB8qIZoQ2Qn+JLxwJCWORv46fKhMM=" },
                { "sha256-base64",      "sha-256",  "base64",   "E+B0JzLRgxm2+1rB8qIZoQ2Qn+JLxwJCWORv46fKhMM=" },
                { "sha256-hex",         "sha-256",  "hex",      "13e0742732d18319b6fb5ac1f2a219a10d909fe24bc7024258e46fe3a7ca84c3" },
                { "sha384-default",     "sha-384",  null,       "F4CFDSBHm+Bm400bOgH2q2IbIUj8XRUBWf0inx7lrN0T8IHz9scGVmJoGZ2+s1La" },
                { "sha384-base64",      "sha-384",  "base64",   "F4CFDSBHm+Bm400bOgH2q2IbIUj8XRUBWf0inx7lrN0T8IHz9scGVmJoGZ2+s1La" },
                { "sha384-hex",         "sha-384",  "hex",      "1780850d20479be066e34d1b3a01f6ab621b2148fc5d150159fd229f1ee5acdd13f081f3f6c706566268199dbeb352da" },
                { "sha512-default",     "sha-512",  null,       "+YpeZRBrctlL1xr6plZOScp/6ArUw3GihjtKys1e3qQ6/aWLFjoOFEfuiUJA3uLIkebH1OG+rDdMFZ0+/JFK2g==" },
                { "sha512-base64",      "sha-512",  "base64",   "+YpeZRBrctlL1xr6plZOScp/6ArUw3GihjtKys1e3qQ6/aWLFjoOFEfuiUJA3uLIkebH1OG+rDdMFZ0+/JFK2g==" },
                { "sha512-hex",         "sha-512",  "hex",      "f98a5e65106b72d94bd71afaa6564e49ca7fe80ad4c371a2863b4acacd5edea43afda58b163a0e1447ee894240dee2c891e6c7d4e1beac374c159d3efc914ada" },
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
    public void hashString() throws CryptoException {
        final String input = "Short string for tests.";
        final String result = Hash.hashString(input, algorithm, null, format);
        assertEquals(expected, result);
    }
}
