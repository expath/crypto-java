/**
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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import ro.kuberam.libs.java.crypto.randomSequencesGeneration.RandomNumber;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class GenerateKeyPair {
	private static Base64.Encoder encoder = Base64.getEncoder();

	public static Map<String, String> run(String algorithm) throws Exception {
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(algorithm);
		keyGenerator.initialize(2048);
		KeyPair keys = keyGenerator.generateKeyPair();

		Map<String, String> result = new HashMap<String, String>();
		result.put("private-key", outputPrivatekey(keys.getPrivate().getEncoded(), algorithm));
		result.put("public-key", outputPublickey(keys.getPublic().getEncoded(), algorithm));

		return result;
	}

	public static KeyPair generate(String algorithm, long seed, String provider) throws Exception {
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(algorithm);
		keyGenerator.initialize(1024, RandomNumber.generate(seed, "SHA1PRNG", provider));

		return keyGenerator.generateKeyPair();
	}

	private static String outputPrivatekey(byte[] privateKey, String algorithm) {
		return "-----BEGIN " + algorithm + " PRIVATE KEY-----\n" + encoder.encodeToString(privateKey)
				+ "\n-----END " + algorithm + " PRIVATE KEY-----\n";
	}

	private static String outputPublickey(byte[] publicKey, String algorithm) {
		return "-----BEGIN " + algorithm + " PUBLIC KEY-----\n" + encoder.encodeToString(publicKey)
				+ "\n-----END " + algorithm + " PUBLIC KEY-----\n";
	}

	public static String savePrivateKey(PrivateKey priv) throws GeneralSecurityException {
		KeyFactory fact = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec spec = fact.getKeySpec(priv, PKCS8EncodedKeySpec.class);
		byte[] packed = spec.getEncoded();
		String key64 = Base64.getEncoder().encodeToString(packed);
		Arrays.fill(packed, (byte) 0);

		return key64;
	}

	public static String savePublicKey(PublicKey publ) throws GeneralSecurityException {
		KeyFactory fact = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec spec = fact.getKeySpec(publ, X509EncodedKeySpec.class);

		return Base64.getEncoder().encodeToString(spec.getEncoded());
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
