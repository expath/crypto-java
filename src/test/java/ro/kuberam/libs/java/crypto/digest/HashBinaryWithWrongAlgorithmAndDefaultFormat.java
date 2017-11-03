package ro.kuberam.libs.java.crypto.digest;

import java.io.InputStream;

import ro.kuberam.libs.java.crypto.ErrorMessages;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertTrue;

public class HashBinaryWithWrongAlgorithmAndDefaultFormat extends BaseTest {

    @Test
    public void hashBinaryWithWrongAlgorithm() throws Exception {
        try (final InputStream input = getClass().getResourceAsStream("../../keystore.ks")) {
            final String result = Hash.hashBinary(input, "SHA-17");
            assertTrue(false);
        } catch (final Exception e) {
            assertTrue(e.getLocalizedMessage().equals(ErrorMessages.error_unknownAlgorithm));
        }
    }
}
