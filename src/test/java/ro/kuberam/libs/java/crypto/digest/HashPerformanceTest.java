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

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;

import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import static org.junit.Assert.assertEquals;
import static ro.kuberam.libs.java.crypto.TestUtils.generate5MbFile;
import static ro.kuberam.libs.java.crypto.TestUtils.generate5MbString;

public class HashPerformanceTest {

    @ClassRule
    public static final TemporaryFolder temporaryFolder = new TemporaryFolder();

    private static Path tempFile;
    private static String tempString;

    @BeforeClass
    public static void initialize() throws IOException {
        tempFile = generate5MbFile(temporaryFolder.newFile("HashPerformanceTest"));
        tempString = generate5MbString();
    }

    @Test
    public void digestInputStreamWithFileInputStreamTest() throws Exception {

        final MessageDigest algorithm = MessageDigest.getInstance("SHA");
        try (final DigestInputStream dis = new DigestInputStream(Files.newInputStream(tempFile), algorithm)) {

            // read the file and update the hash calculation
            while (dis.read() != -1)
                ;

            // get the hash value as byte array
            byte[] hash = algorithm.digest();

            assertEquals(20, hash.length);
        }
    }

    @Test
    public void digestInputStreamWithBufferedInputStreamTest() throws Exception {
        final MessageDigest algorithm = MessageDigest.getInstance("SHA");
        try (final BufferedInputStream bis = new BufferedInputStream(Files.newInputStream(tempFile));
             final DigestInputStream dis = new DigestInputStream(bis, algorithm)) {

            // read the file and update the hash calculation
            while (dis.read() != -1)
                ;

            // get the hash value as byte array
            final byte[] hash = algorithm.digest();

            assertEquals(20, hash.length);
        }
    }

    @Test
    public void digestStringWithInputStreamTest() throws Exception {

        MessageDigest algorithm = MessageDigest.getInstance("SHA");
        try (final InputStream is = new ByteArrayInputStream(tempString.getBytes(StandardCharsets.UTF_8));
             final DigestInputStream dis = new DigestInputStream(is, algorithm)) {

            // read the file and update the hash calculation
            while (dis.read() != -1)
                ;

            // get the hash value as byte array
            final byte[] hash = algorithm.digest();

            assertEquals(20, hash.length);
        }
    }

    @Test
    public void digestString() throws Exception {
        final MessageDigest algorithm = MessageDigest.getInstance("SHA");
        algorithm.update(tempString.getBytes(StandardCharsets.UTF_8));
        final byte[] hash = algorithm.digest();

        assertEquals(20, hash.length);
    }

    @Test
    @Ignore("too slow")
    public void digestWithByteArrayOutputStreamTest() throws Exception {
        final byte[] tempBa = Files.readAllBytes(tempFile);
        int tempByteArrayLength = tempBa.length;
        final MessageDigest algorithm = MessageDigest.getInstance("SHA");

        while (tempByteArrayLength > 0) {
            algorithm.update(tempBa, 0, tempByteArrayLength);
            tempByteArrayLength = tempBa.length;
        }

        // get the hash value as byte array
        final byte[] hash = algorithm.digest();

        assertEquals(20, hash.length);
    }

}
