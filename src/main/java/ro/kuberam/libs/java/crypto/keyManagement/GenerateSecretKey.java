package ro.kuberam.libs.java.crypto.keyManagement;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class GenerateSecretKey {

	public static SecretKey run(String algorithm) {
		KeyGenerator keyGen = null;
		try {
			/*
			 * Get KeyGenerator object that generates secret keys for the specified
			 * algorithm.
			 */
			keyGen = KeyGenerator.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		/* Initializes this key generator for key size to 256. */
		keyGen.init(256);

		/* Generates a secret key */
		SecretKey secretKey = keyGen.generateKey();

		return secretKey;
	}

	public static void main(String args[]) {
		SecretKey secretKey = run("AES");
		String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
		System.out.println(encodedKey);
	}
}