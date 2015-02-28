package ro.kuberam.libs.java.crypto.secureStorage;

import java.security.Key;
import java.security.cert.Certificate;

public class AddEntry {
	
	public boolean add() {
		
		boolean added = true;
		
		return added;
	}
	
	private boolean addKey(String alias, Key key, char[] password, Certificate[] certificateChain) {
		
		boolean added = true;
		
		return added;
	}
	
	private boolean addCertificate(String alias, Certificate certificate) {
		
		boolean added = true;
		
		return added;
	}
}

//import java.security.*;
//import java.security.spec.*;
//import java.security.cert.*;
//import java.io.*;
//import java.util.*;
//
//public class KeyStoreImport {
//
//	public static void main(String args[]) {
//		try {
//			// Meaningful variable names for the arguments
//			String keyStoreFileName = args[0];
//			String certificateChainFileName = args[1];
//			String privateKeyFileName = args[2];
//			String entryAlias = args[3];
//
//			// Get the password for the keystore.
//			System.out.println("Keystore password:  ");
//
//			String keyStorePassword = (new BufferedReader(
//					new InputStreamReader(System.in))).readLine();
//
//			// Load the keystore
//			KeyStore keyStore = KeyStore.getInstance("jks");
//			FileInputStream keyStoreInputStream = new FileInputStream(
//					keyStoreFileName);
//			keyStore.load(keyStoreInputStream, keyStorePassword.toCharArray());
//			keyStoreInputStream.close();
//
//			// Load the certificate chain (in X.509 DER encoding).
//			FileInputStream certificateStream = new FileInputStream(
//					certificateChainFileName);
//			CertificateFactory certificateFactory = CertificateFactory
//					.getInstance("X.509");
//			// Required because Java is STUPID. You can't just cast the result
//			// of toArray to Certificate[].
//			java.security.cert.Certificate[] chain = {};
//			chain = certificateFactory.generateCertificates(certificateStream)
//					.toArray(chain);
//			certificateStream.close();
//
//			// Load the private key (in PKCS#8 DER encoding).
//			File keyFile = new File(privateKeyFileName);
//			byte[] encodedKey = new byte[(int) keyFile.length()];
//			FileInputStream keyInputStream = new FileInputStream(keyFile);
//			keyInputStream.read(encodedKey);
//			keyInputStream.close();
//			KeyFactory rSAKeyFactory = KeyFactory.getInstance("RSA");
//			PrivateKey privateKey = rSAKeyFactory
//					.generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
//
//			// Add the new entry
//			System.out.println("Private key entry password:  ");
//
//			String privateKeyEntryPassword = (new BufferedReader(
//					new InputStreamReader(System.in))).readLine();
//			keyStore.setEntry(entryAlias, new KeyStore.PrivateKeyEntry(
//					privateKey, chain), new KeyStore.PasswordProtection(
//					privateKeyEntryPassword.toCharArray()));
//
//			// Write out the keystore
//			FileOutputStream keyStoreOutputStream = new FileOutputStream(
//					keyStoreFileName);
//			keyStore.store(keyStoreOutputStream, keyStorePassword.toCharArray());
//			keyStoreOutputStream.close();
//		}
//
//		catch (Exception e) {
//			e.printStackTrace();
//			System.exit(1);
//		}
//	}
//}



//import java.io.*;
//import java.security.*;
//import javax.crypto.*;
//import javax.crypto.spec.*;
//import java.util.*;
//
//public class StoreKey
//{
//   private static String keyFile, cipherFile;
//   private static String password;
//   private static FileOutputStream keyOutFile, cipherOutFile;
//
//   public static void main(String[] args) throws Exception
//   {
//
//      // Create the password key and initialize the cipher
//      // for encryption
//
//      String password = "super_secret_password";
//      PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
//      SecretKeyFactory keyFactory =
//          SecretKeyFactory.getInstance("PBEWithMD5AndDES");
//      SecretKey passwordKey = keyFactory.generateSecret(keySpec);
//
//      byte[] salt = new byte[8];
//      Random rnd = new Random();
//      rnd.nextBytes(salt);
//      int iterations = 1000;
//
//      PBEParameterSpec parameterSpec = new PBEParameterSpec(salt, iterations);
//
//      Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
//      cipher.init(Cipher.ENCRYPT_MODE, passwordKey, parameterSpec);
//
//
//      // Create a secret key using the DESede algorithm which
//      // may be used by applications for symmetric encryption.
//
//      KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
//      keyGenerator.init(168);
//      SecretKey secretKey = keyGenerator.generateKey();
//
//      // Write something encrypted to a file ("secretStuff") with
//      // this secret key
//
//      String clearText = "I sure love working with the JCE.";
//      byte[] clearTextBytes = clearText.getBytes("UTF8");
//
//      Cipher cipher2 = Cipher.getInstance("DESede");
//      cipher2.init(Cipher.ENCRYPT_MODE, secretKey);
//
//      byte[] cipherBytes = cipher2.doFinal(clearTextBytes);
//
//      // A little "hack" here to see how many bytes were encoded.
//      // This value will be "hardcoded" in RetrieveKey.java
//
//      System.out.println(cipherBytes.length);
//
//      cipherFile = "secretStuff";
//      cipherOutFile = new FileOutputStream(cipherFile);
//
//      cipherOutFile.write(cipherBytes);
//
//      cipherOutFile.close();
//
//      // Get the bytes of this secret key and encrypted them,
//
//      byte[] secretKeyBytes = secretKey.getEncoded();
//      byte[] secretKeyBytesEncrypted = cipher.doFinal(secretKeyBytes);
//
//      // A little "hack" to see how many bytes make up the encrypted
//      // secret key.
//
//      System.out.println(secretKeyBytesEncrypted.length);
//
//      // Write the salt and the encrypted secret key to the file;
//      // salt is needed when reconstructing the PBE key for decryption.
//
//      keyFile = "key.bin";
//      keyOutFile = new FileOutputStream(keyFile);
//
//      keyOutFile.write(salt);
//      keyOutFile.write(secretKeyBytesEncrypted);
//
//      keyOutFile.close();
//   }
//}