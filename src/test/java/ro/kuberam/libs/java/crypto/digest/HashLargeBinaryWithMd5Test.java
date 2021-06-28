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

import java.io.InputStream;
import java.nio.file.Files;

import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class HashLargeBinaryWithMd5Test extends BaseTest {

    @Test
    public void hashLargeBinaryWithMd5() throws Exception {
        try (final InputStream is = Files.newInputStream(generate5MbTempFile().toPath())) {
            final String result = Hash.hashBinary(is, "MD5", "base64");
            Assert.assertTrue(result.equals("fSAcOQGKiTzr20UUJWNpaQ=="));
        }
    }
}
