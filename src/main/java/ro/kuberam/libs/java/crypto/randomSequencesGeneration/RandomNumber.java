package ro.kuberam.libs.java.crypto.randomSequencesGeneration;

import java.security.SecureRandom;

public class RandomNumber {

    public static SecureRandom generate(final long seed, final String algorithm, final String provider)
            throws Exception {
        final SecureRandom randomNumber = SecureRandom.getInstance(algorithm, provider);
        randomNumber.setSeed(seed);
        return randomNumber;
    }

    public static SecureRandom generate(final String algorithm, final String provider) throws Exception {
        final SecureRandom randomNumber = SecureRandom.getInstance(algorithm, provider);
        return randomNumber;
    }

    public static void main(final String args[]) throws Exception {
        final SecureRandom randomNumber = generate(1008, "SHA1PRNG", "SUN");
        System.out.println("Random number:\n" + randomNumber.nextLong());
    }

}
