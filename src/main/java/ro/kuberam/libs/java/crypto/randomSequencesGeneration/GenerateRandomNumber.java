package ro.kuberam.libs.java.crypto.randomSequencesGeneration;

import java.security.SecureRandom;

public class GenerateRandomNumber {
	
	public static SecureRandom generateRandomNumber(long seed, String algorithm, String provider) throws Exception {
		SecureRandom randomNumber = SecureRandom.getInstance(algorithm, provider);
		randomNumber.setSeed(seed);

		return randomNumber;
	}
	
	public static void main(String args[]) throws Exception {

		SecureRandom randomNumber = generateRandomNumber(1008, "SHA1PRNG", "base64");

		System.out.println("Random number:\n" + randomNumber);
	}

}
