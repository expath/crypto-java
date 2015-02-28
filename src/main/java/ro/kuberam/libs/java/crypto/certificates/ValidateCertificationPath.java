package ro.kuberam.libs.java.crypto.certificates;

import java.io.File;
import java.io.FileInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertificateException;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;

public class ValidateCertificationPath {
	
	public static byte[] validate(CertPath certPath) throws Exception {
	
	try {
		//TODO: pay attention that this class maybe uses deprecated java.security.*
		
	    // Load the JDK's cacerts keystore file
	    String filename = System.getProperty("java.home")
	        + "/lib/security/cacerts".replace('/', File.separatorChar);
	    FileInputStream is = new FileInputStream(filename);
	    KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
	    String password = "changeit";
	    keystore.load(is, password.toCharArray());

	    // Create the parameters for the validator
	    PKIXParameters params = new PKIXParameters(keystore);

	    // Disable CRL checking since we are not supplying any CRLs
	    params.setRevocationEnabled(false);

	    // Create the validator and validate the path
	    // To create a path, see Creating a Certification Path
	    CertPathValidator certPathValidator
	        = CertPathValidator.getInstance(CertPathValidator.getDefaultType());
	    CertPathValidatorResult result = certPathValidator.validate(certPath, params);

	    // Get the CA used to validate this path
	    PKIXCertPathValidatorResult pkixResult = (PKIXCertPathValidatorResult)result;
	    TrustAnchor ta = pkixResult.getTrustAnchor();
	    java.security.cert.X509Certificate cert = ta.getTrustedCert();
	} catch (CertificateException e) {
	} catch (KeyStoreException e) {
	} catch (NoSuchAlgorithmException e) {
	} catch (InvalidAlgorithmParameterException e) {
	} catch (CertPathValidatorException e) {
	    // Validation failed
	}
	return null;
	
}

}
