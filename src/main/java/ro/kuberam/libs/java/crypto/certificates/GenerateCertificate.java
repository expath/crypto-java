package ro.kuberam.libs.java.crypto.certificates;


public class GenerateCertificate {
	
//	  public static void main(String[] args) throws Exception {
//		    String keystoreFile = "keyStoreFile.bin";
//		    String caAlias = "caAlias";
//		    String certToSignAlias = "cert";
//		    String newAlias = "newAlias";
//
//		    char[] password = new char[]{'a','b','c','d','e','f','g','h'};
//		    char[] caPassword = new char[]{'a','b','c','d','e','f','g','h'};
//		    char[] certPassword = new char[]{'a','b','c','d','e','f','g','h'};
//
//		    FileInputStream input = new FileInputStream(keystoreFile);
//		    KeyStore keyStore = KeyStore.getInstance("JKS");
//		    keyStore.load(input, password);
//		    input.close();
//
//		    PrivateKey caPrivateKey = (PrivateKey) keyStore.getKey(caAlias, caPassword);
//		    java.security.cert.Certificate caCert = keyStore.getCertificate(caAlias);
//
//		    byte[] encoded = caCert.getEncoded();
//		    X509CertImpl caCertImpl = new X509CertImpl(encoded);
//
//		    X509CertInfo caCertInfo = (X509CertInfo) caCertImpl.get(X509CertImpl.NAME + "."
//		        + X509CertImpl.INFO);
//
//		    X500Name issuer = (X500Name) caCertInfo.get(X509CertInfo.SUBJECT + "."
//		        + CertificateIssuerName.DN_NAME);
//
//		    java.security.cert.Certificate cert = keyStore.getCertificate(certToSignAlias);
//		    PrivateKey privateKey = (PrivateKey) keyStore.getKey(certToSignAlias, certPassword);
//		    encoded = cert.getEncoded();
//		    X509CertImpl certImpl = new X509CertImpl(encoded);
//		    X509CertInfo certInfo = (X509CertInfo) certImpl
//		        .get(X509CertImpl.NAME + "." + X509CertImpl.INFO);
//
//		    Date firstDate = new Date();
//		    Date lastDate = new Date(firstDate.getTime() + 365 * 24 * 60 * 60 * 1000L);
//		    CertificateValidity interval = new CertificateValidity(firstDate, lastDate);
//
//		    certInfo.set(X509CertInfo.VALIDITY, interval);
//
//		    certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(
//		        (int) (firstDate.getTime() / 1000)));
//
//		    certInfo.set(X509CertInfo.ISSUER + "." + CertificateSubjectName.DN_NAME, issuer);
//
//		    AlgorithmId algorithm = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
//		    certInfo.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algorithm);
//		    X509CertImpl newCert = new X509CertImpl(certInfo);
//
//		    newCert.sign(caPrivateKey, "MD5WithRSA");
//
//		    keyStore.setKeyEntry(newAlias, privateKey, certPassword,
//		        new java.security.cert.Certificate[] { newCert });
//
//		    FileOutputStream output = new FileOutputStream(keystoreFile);
//		    keyStore.store(output, password);
//		    output.close();
//
//		  }
	
//    public static X509Certificate generateV1Certificate(KeyPair pair)
//            throws InvalidKeyException, NoSuchProviderException, SignatureException, CertificateEncodingException, IllegalStateException, NoSuchAlgorithmException
//        {
//            Security.addProvider(new BouncyCastleProvider());
//            // generate the certificate
//            X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
//
//
//            certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
//            certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
//            certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
//            certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
//            certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
//            certGen.setPublicKey(pair.getPublic());
//            certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
//
//            return certGen.generate(pair.getPrivate(), "BC");
//        }
//
//      public static KeyPair generateRSAKeyPair() throws Exception {
//        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
//        kpGen.initialize(1024, new SecureRandom());
//        return kpGen.generateKeyPair();
//      }
//
//        public static void main( String[] args) throws Exception {
//
//            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
//
//            KeyPair pair = generateRSAKeyPair();
//
//            // generate the certificate
//            X509Certificate cert = generateV1Certificate(pair);
//
//            // show some basic validation
//            cert.checkValidity(new Date());
//
//            cert.verify(cert.getPublicKey());
//
//            //System.out.println("Certificate for: " + cert );
//            
//            byte[] buf = cert.getEncoded();
//            FileOutputStream os = new FileOutputStream("mycert.cer");
//            Writer wr = new OutputStreamWriter(os, Charset.forName("UTF-8"));
//            wr.write("-----BEGIN CERTIFICATE-----\n");
//            wr.write(Base64.encodeToString( buf, true ));
//            wr.write("\n-----END CERTIFICATE-----\n");
//            wr.flush();
//            os.close();
//
//            //get certificate from fileC:\working
//            CertificateFactory x509CertFact = CertificateFactory.getInstance("X.509");
//            FileInputStream fis = new FileInputStream("mycert.cer");
//            X509Certificate certRetrieved = (X509Certificate) x509CertFact.generateCertificate(fis);
//            fis.close();
//
//        System.out.println(pair.getPrivate());
//            
//        }
	
	/* Creating a Self-Signed Version 3 Certificate
	import java.math.BigInteger;
	import java.security.InvalidKeyException;
	import java.security.KeyPair;
	import java.security.KeyPairGenerator;
	import java.security.NoSuchProviderException;
	import java.security.SecureRandom;
	import java.security.Security;
	import java.security.SignatureException;
	import java.security.cert.X509Certificate;
	import java.util.Date;

	import javax.security.auth.x500.X500Principal;

	import org.bouncycastle.asn1.x509.BasicConstraints;
	import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
	import org.bouncycastle.asn1.x509.GeneralName;
	import org.bouncycastle.asn1.x509.GeneralNames;
	import org.bouncycastle.asn1.x509.KeyPurposeId;
	import org.bouncycastle.asn1.x509.KeyUsage;
	import org.bouncycastle.asn1.x509.X509Extensions;
	import org.bouncycastle.x509.X509V3CertificateGenerator;

	public class MainClass {
	  public static X509Certificate generateV3Certificate(KeyPair pair) throws InvalidKeyException,
	      NoSuchProviderException, SignatureException {
	    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

	    X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

	    certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
	    certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
	    certGen.setNotBefore(new Date(System.currentTimeMillis() - 10000));
	    certGen.setNotAfter(new Date(System.currentTimeMillis() + 10000));
	    certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
	    certGen.setPublicKey(pair.getPublic());
	    certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

	    certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
	    certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature
	        | KeyUsage.keyEncipherment));
	    certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(
	        KeyPurposeId.id_kp_serverAuth));

	    certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(
	        new GeneralName(GeneralName.rfc822Name, "test@test.test")));

	    return certGen.generateX509Certificate(pair.getPrivate(), "BC");
	  }

	  public static void main(String[] args) throws Exception {
	    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

	    KeyPair pair = generateRSAKeyPair();
	    X509Certificate cert = generateV3Certificate(pair);
	    cert.checkValidity(new Date());
	    cert.verify(cert.getPublicKey());
	  }
	  public static KeyPair generateRSAKeyPair() throws Exception {
	    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
	    kpGen.initialize(1024, new SecureRandom());
	    return kpGen.generateKeyPair();
	  }
	}
	 */

	/*
	 * Use X.509 certificate
	import java.io.BufferedWriter;
	import java.io.FileInputStream;
	import java.io.FileOutputStream;
	import java.io.OutputStreamWriter;
	import java.security.cert.Certificate;
	import java.security.cert.CertificateFactory;

	public class MainClass {

	  public static void main(String args[]) throws Exception {
	    CertificateFactory cf = CertificateFactory.getInstance("X.509");
	    FileInputStream in = new FileInputStream(args[0]);
	    Certificate c = cf.generateCertificate(in);
	    in.close();
	    String s = c.toString();
	    FileOutputStream fout = new FileOutputStream("tmp.txt");
	    BufferedWriter out = new BufferedWriter(new OutputStreamWriter(fout));
	    out.write(s, 0, s.length());
	    out.close();

	  }

	}
	 */

}
