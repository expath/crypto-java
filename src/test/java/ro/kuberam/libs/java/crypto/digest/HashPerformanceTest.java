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
import org.junit.Ignore;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertTrue;

public class HashPerformanceTest extends BaseTest {

    private static Path tempFile;
    private static String tempString;

    @BeforeClass
    public static void initialize() throws IOException {
        tempFile = generate5MbTempFile().toPath();
        tempString = generate5MbTempString();
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

            assertTrue(hash.length == 20);
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

            assertTrue(hash.length == 20);
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

            assertTrue(hash.length == 20);
        }
    }

    @Test
    public void digestString() throws Exception {
        final MessageDigest algorithm = MessageDigest.getInstance("SHA");
        algorithm.update(tempString.getBytes(StandardCharsets.UTF_8));
        final byte[] hash = algorithm.digest();

        assertTrue(hash.length == 20);
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

        assertTrue(hash.length == 20);
    }

}
