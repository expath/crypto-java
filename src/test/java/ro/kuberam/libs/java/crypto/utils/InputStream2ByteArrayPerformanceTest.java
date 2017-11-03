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
