package ro.kuberam.libs.java.crypto.encrypt;

import ro.kuberam.libs.java.crypto.digest.Hash;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertEquals;

public class EncryptStringWithAesSymmetricKeyAndDefaultProviderCbcMode extends BaseTest {

    @Test
    public void encryptStringWithAesSymmetricKey() throws Exception {
        final String input = "Short string for tests.";
        final String plainKey = "1234567890123456";
        final String iv = Hash.hashString("initialization vector", "MD5", "");

        final String result = SymmetricEncryption.encryptString(input, plainKey, "AES/CBC/PKCS5Padding", iv, "");

        assertEquals("51-143-171-200-187-20-34-252-231-243-254-42-36-13-9-123-191-251-243-42-3-238-193-13-155-168-139-67-135-3-143-54", result);
    }
}
