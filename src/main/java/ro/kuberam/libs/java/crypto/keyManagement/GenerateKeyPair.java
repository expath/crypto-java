package ro.kuberam.libs.java.crypto.keyManagement;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import ro.kuberam.libs.java.crypto.randomSequencesGeneration.RandomNumber;

public class GenerateKeyPair {

	public static KeyPair generate(String algorithm) throws Exception {
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("DSA");
		keyGenerator.initialize(1024, RandomNumber.generate("SHA1PRNG", "SUN"));

		return (keyGenerator.generateKeyPair());
	}

	public static KeyPair generate(long seed, String algorithm, String provider) throws Exception {
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("DSA");
		keyGenerator.initialize(1024, RandomNumber.generate(seed, "SHA1PRNG", provider));

		return (keyGenerator.generateKeyPair());
	}

	public static void main(String args[]) throws Exception {

		KeyPair keyPair = generate(1008, "SHA1PRNG", "base64");

		System.out.println("Private key:\n" + keyPair.getPrivate());

		System.out.println("Public key:\n" + keyPair.getPublic());
	}

}
