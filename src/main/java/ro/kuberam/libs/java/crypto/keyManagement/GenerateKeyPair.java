package ro.kuberam.libs.java.crypto.keyManagement;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import ro.kuberam.libs.java.crypto.randomSequencesGeneration.RandomNumber;
import java.util.Base64;

public class GenerateKeyPair {

	public static KeyPair generate(String algorithm) throws Exception {
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(algorithm);
		keyGenerator.initialize(1024, RandomNumber.generate("SHA1PRNG", "SUN"));

		return (keyGenerator.generateKeyPair());
	}

	public static KeyPair generate(long seed, String algorithm, String provider) throws Exception {
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(algorithm);
		keyGenerator.initialize(1024, RandomNumber.generate(seed, "SHA1PRNG", provider));

		return (keyGenerator.generateKeyPair());
	}

	public static String savePrivateKey(PrivateKey priv) throws GeneralSecurityException {
		KeyFactory fact = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec spec = fact.getKeySpec(priv, PKCS8EncodedKeySpec.class);
		byte[] packed = spec.getEncoded();
		String key64 = Base64.getEncoder().encodeToString(packed);

		Arrays.fill(packed, (byte) 0);
		return key64;
	}

	public static void main(String args[]) throws Exception {

		KeyPair keyPair = generate("RSA");

		System.out.println("Private key:\n" + Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));

		// System.out.println("Private key:\n" +
		// savePrivateKey(keyPair.getPrivate()));

		System.out.println("Public key:\n" + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
	}

}

// public static PrivateKey loadPrivateKey(String key64) throws
// GeneralSecurityException {
// byte[] clear = base64Decode(key64);
// PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
// KeyFactory fact = KeyFactory.getInstance("DSA");
// PrivateKey priv = fact.generatePrivate(keySpec);
// Arrays.fill(clear, (byte) 0);
// return priv;
// }
//
//
// public static PublicKey loadPublicKey(String stored) throws
// GeneralSecurityException {
// byte[] data = base64Decode(stored);
// X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
// KeyFactory fact = KeyFactory.getInstance("DSA");
// return fact.generatePublic(spec);
// }
//
// public static String savePublicKey(PublicKey publ) throws
// GeneralSecurityException {
// KeyFactory fact = KeyFactory.getInstance("DSA");
// X509EncodedKeySpec spec = fact.getKeySpec(publ,
// X509EncodedKeySpec.class);
// return base64Encode(spec.getEncoded());
// }
//
//
// public static void main(String[] args) throws Exception {
// KeyPairGenerator gen = KeyPairGenerator.getInstance("DSA");
// KeyPair pair = gen.generateKeyPair();
//
// String pubKey = savePublicKey(pair.getPublic());
// PublicKey pubSaved = loadPublicKey(pubKey);
// System.out.println(pair.getPublic()+"\n"+pubSaved);
//
// String privKey = savePrivateKey(pair.getPrivate());
// PrivateKey privSaved = loadPrivateKey(privKey);
// System.out.println(pair.getPrivate()+"\n"+privSaved);
// }
