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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

class DsaKeyGenerator {
	public static void main(String[] a) {
		int keySize = 1024;
		String output = "aa";
		String algorithm = "DSA";
		try {
			genKeyPair(keySize, output, algorithm);
		} catch (Exception e) {
			System.out.println("Exception: " + e);
			return;
		}
	}

	private static void genKeyPair(int keySize, String output, String algorithm) throws Exception {
		KeyPairGenerator kg = KeyPairGenerator.getInstance(algorithm, "SUN");
		kg.initialize(keySize);
		System.out.println();
		System.out.println("KeyPairGenerator Object Info: ");
		System.out.println("Algorithm = " + kg.getAlgorithm());
		System.out.println("Provider = " + kg.getProvider());
		System.out.println("Key Size = " + keySize);
		System.out.println("toString = " + kg.toString());
		KeyPair pair = kg.generateKeyPair();
		PrivateKey priKey = pair.getPrivate();
		PublicKey pubKey = pair.getPublic();
		byte[] ky = priKey.getEncoded();

		System.out.println();
		System.out.println("Private Key Info: ");
		System.out.println("Algorithm = " + priKey.getAlgorithm());
		System.out.println("Size = " + ky.length);
		System.out.println("Format = " + priKey.getFormat());
		System.out.println("toString = " + Base64.getEncoder().encodeToString(priKey.getEncoded()));

		System.out.println();
		System.out.println("Public Key Info: ");
		System.out.println("Algorithm = " + pubKey.getAlgorithm());
		System.out.println("Size = " + ky.length);
		System.out.println("Format = " + pubKey.getFormat());
		System.out.println("toString = " + Base64.getEncoder().encodeToString(pubKey.getEncoded()));
	}
}