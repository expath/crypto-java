package ro.kuberam.libs.java.crypto.encrypt;

import ro.kuberam.libs.java.crypto.ErrorMessages;
import ro.kuberam.libs.java.crypto.digest.Hash;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertTrue;

public class EncryptStringWithAesWrongSymmetricKeyCbcMode extends BaseTest {

    @Test
    public void encryptStringWithAesWrongSymmetricKey() throws Exception {
        final String input = "Short string for tests.";
        final String plainKey = "12345678901234567";
        final String iv = Hash.hashString("initialization vector", "MD5", "");

        try {
            final String result = SymmetricEncryption.encryptString(input, plainKey, "AES/CBC/PKCS5Padding", iv, "SunJCE");
            assertTrue(false);
        } catch (final Exception e) {
            assertTrue(e.getLocalizedMessage().equals(ErrorMessages.error_cryptoKey));
        }
    }
}
