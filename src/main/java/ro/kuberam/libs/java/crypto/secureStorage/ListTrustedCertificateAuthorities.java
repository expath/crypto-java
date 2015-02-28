package ro.kuberam.libs.java.crypto.secureStorage;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
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
	
	public static void main(String[] args) {
        try {
            // Load the JDK's cacerts keystore file
            String filename = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar);
            FileInputStream is = new FileInputStream(filename);
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            String password = "changeit";
            keystore.load(is, password.toCharArray());

            // This class retrieves the most-trusted CAs from the keystore
            PKIXParameters params = new PKIXParameters(keystore);

            // Get the set of trust anchors, which contain the most-trusted CA certificates
            Iterator<TrustAnchor> it = params.getTrustAnchors().iterator();
            while( it.hasNext() ) {
                TrustAnchor ta = (TrustAnchor)it.next();
                // Get certificate
                X509Certificate cert = ta.getTrustedCert();
                System.out.println(cert.getIssuerDN());
            }
        } catch (CertificateException e) {
        } catch (KeyStoreException e) {
        } catch (NoSuchAlgorithmException e) {
        } catch (InvalidAlgorithmParameterException e) {
        } catch (IOException e) {
        } 
    }


}
