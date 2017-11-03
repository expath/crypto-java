package ro.kuberam.libs.java.crypto.encrypt;

import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertEquals;

public class DecryptStringWithAesSymmetricKeyEcbMode extends BaseTest {

    @Test
    public void decryptStringWithAesSymmetricKey() throws Exception {
        final String input = "222-157-20-54-132-99-46-30-73-43-253-148-61-155-86-141-51-56-40-42-31-168-189-56-236-102-58-237-175-171-9-87";
        final String plainKey = "1234567890123456";

        final String result = SymmetricEncryption.decryptString(input, plainKey, "AES", "", "SunJCE");

        assertEquals("Short string for tests.", result);
    }
}
