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
package ro.kuberam.libs.java.crypto.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.Before;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertEquals;

public class InputStream2ByteArrayPerformanceTest extends BaseTest {

    private static Path tempFile;

    @Before
    public void initialize() throws IOException {
        tempFile = generate5MbTempFile().toPath();
    }

    @Test
    public void byteArrayOutputStreamTest() throws Exception {

        try (final InputStream is = Files.newInputStream(tempFile);
             final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            int next = is.read();
            while (next > -1) {
                baos.write(next);
                next = is.read();
            }
            baos.flush();
            final byte[] byteArray = baos.toByteArray();

            assertEquals(5200000, byteArray.length);
        }
    }

}
