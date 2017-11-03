package ro.kuberam.libs.java.crypto.secureStorage;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Iterator;

public class ListTrustedCertificateAuthorities {

    public static void main(final String[] args) {
        // Load the JDK's cacerts keystore file
        final Path filename = Paths.get(System.getProperty("java.home"), "lib", "security", "cacerts");
        try (final InputStream is = Files.newInputStream(filename)) {
            final KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            final String password = "changeit";
            keystore.load(is, password.toCharArray());

            // This class retrieves the most-trusted CAs from the keystore
            final PKIXParameters params = new PKIXParameters(keystore);

            // Get the set of trust anchors, which contain the most-trusted CA certificates
            final Iterator<TrustAnchor> it = params.getTrustAnchors().iterator();
            while (it.hasNext()) {
                final TrustAnchor ta = (TrustAnchor) it.next();
                // Get certificate
                final X509Certificate cert = ta.getTrustedCert();
                System.out.println(cert.getIssuerDN());
            }
        } catch (final CertificateException | KeyStoreException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | IOException e) {
            //what?
        }
    }
}
