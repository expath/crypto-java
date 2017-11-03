package ro.kuberam.libs.java.crypto.secureStorage;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class CreateSecureStore {

    public static byte[] create(final String password) throws NoSuchAlgorithmException, CertificateException,
            IOException, KeyStoreException {

        final KeyStore ks = KeyStore.getInstance("JKS");
        final char[] passwordCharArray = password.toCharArray();

        ks.load(null, passwordCharArray);

        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            ks.store(baos, passwordCharArray);
            return baos.toByteArray();
        }
    }

    public static void main(final String[] args) throws Exception {
        System.out.println(new String(create("password")));
    }

}
