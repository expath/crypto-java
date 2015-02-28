package ro.kuberam.libs.java.crypto.certificates;

import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;

public class GenerateCertificationPath {
	
	public static CertPath createCertPath(java.security.cert.Certificate[] certs) {
	    try {
	        CertificateFactory certFact = CertificateFactory.getInstance("X.509");
	        CertPath path = certFact.generateCertPath(Arrays.asList(certs));
	        return path;
	    } catch (java.security.cert.CertificateEncodingException e) {
	    } catch (CertificateException e) {
	    }
	    return null;
	}

}
