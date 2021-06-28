/*
 * EXPath Cryptographic Module
 * Java Library providing an EXPath Cryptographic Module
 * Copyright (C) 2015 Kuberam
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
package ro.kuberam.libs.java.crypto.keyManagement;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import ro.kuberam.libs.java.crypto.randomSequencesGeneration.RandomNumber;

public class GenerateKeyPair {
	private static Base64.Encoder encoder = Base64.getEncoder();

	public static GeneratedKeys run(String algorithm) throws Exception {
		KeyPairGenerator keyGenerator = getKeyPairGenerator(algorithm);
		keyGenerator.initialize(2048);
		KeyPair keys = keyGenerator.generateKeyPair();

		final String privateKey = outputPrivatekey(keys.getPrivate().getEncoded(), algorithm);
		final String publicKey = outputPublickey(keys.getPublic().getEncoded(), algorithm);

		return new GeneratedKeys(privateKey, publicKey);
	}

	public static GeneratedKeys run(String algorithm, String provider) throws Exception {
		KeyPairGenerator keyGenerator = getKeyPairGenerator(algorithm, provider);
		keyGenerator.initialize(2048);
		KeyPair keys = keyGenerator.generateKeyPair();

		final String privateKey = outputPrivatekey(keys.getPrivate().getEncoded(), algorithm);
		final String publicKey = outputPublickey(keys.getPublic().getEncoded(), algorithm);

		return new GeneratedKeys(privateKey, publicKey);
	}

	public static KeyPair generate(String algorithm, long seed, String provider) throws Exception {
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(algorithm);
		keyGenerator.initialize(1024, RandomNumber.generate(seed, "SHA1PRNG", provider));

		return keyGenerator.generateKeyPair();
	}

	private static String outputPrivatekey(byte[] privateKey, String algorithm) {
		return "-----BEGIN " + algorithm + " PRIVATE KEY-----\n" + encoder.encodeToString(privateKey) + "\n-----END "
				+ algorithm + " PRIVATE KEY-----\n";
	}

	private static String outputPublickey(byte[] publicKey, String algorithm) {
		return "-----BEGIN " + algorithm + " PUBLIC KEY-----\n" + encoder.encodeToString(publicKey) + "\n-----END "
				+ algorithm + " PUBLIC KEY-----\n";
	}

	private static KeyPairGenerator getKeyPairGenerator(String algorithm) throws NoSuchAlgorithmException {
		return KeyPairGenerator.getInstance(algorithm);
	}
	
	private static KeyPairGenerator getKeyPairGenerator(String algorithm, String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
		return KeyPairGenerator.getInstance(algorithm, provider);
	}	

	public static String savePrivateKey(PrivateKey priv) throws GeneralSecurityException {
		KeyFactory fact = KeyFactory.getInstance("EllipticCurve");
		PKCS8EncodedKeySpec spec = fact.getKeySpec(priv, PKCS8EncodedKeySpec.class);

		return Base64.getEncoder().encodeToString(spec.getEncoded());
	}

	public static String savePublicKey(PublicKey publ) throws GeneralSecurityException {
		KeyFactory fact = KeyFactory.getInstance("EllipticCurve");
		X509EncodedKeySpec spec = fact.getKeySpec(publ, X509EncodedKeySpec.class);

		return Base64.getEncoder().encodeToString(spec.getEncoded());
	}

	public static class GeneratedKeys {
		private final String privateKey;
		private final String publicKey;

		public GeneratedKeys(final String privateKey, final String publicKey) {
			this.privateKey = privateKey;
			this.publicKey = publicKey;
		}

		public String getPrivateKey() {
			return privateKey;
		}

		public String getPublicKey() {
			return publicKey;
		}
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
