package ro.kuberam.libs.java.crypto.certificates;

import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;

public class GenerateCertificationPath {

    public static CertPath createCertPath(final java.security.cert.Certificate[] certs) {
        try {
            final CertificateFactory certFact = CertificateFactory.getInstance("X.509");
            final CertPath path = certFact.generateCertPath(Arrays.asList(certs));
            return path;
        } catch (final java.security.cert.CertificateEncodingException e) {
        } catch (final CertificateException e) {
        }
        return null;
    }

}
