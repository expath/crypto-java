package ro.kuberam.libs.java.crypto.randomSequencesGeneration;

import java.security.SecureRandom;

public class RandomNumber {

	public static SecureRandom generate(long seed, String algorithm, String provider)
			throws Exception {
		SecureRandom randomNumber = SecureRandom.getInstance(algorithm, provider);
		randomNumber.setSeed(seed);

		return randomNumber;
	}

	public static SecureRandom generate(String algorithm, String provider) throws Exception {
		SecureRandom randomNumber = SecureRandom.getInstance(algorithm, provider);

		return randomNumber;
	}

	public static void main(String args[]) throws Exception {

		SecureRandom randomNumber = generate(1008, "SHA1PRNG", "SUN");

		System.out.println("Random number:\n" + randomNumber.nextLong());
	}

}
