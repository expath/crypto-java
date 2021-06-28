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
package ro.kuberam.libs.java.crypto.providers.defaultProvider;

import java.security.AccessController;
import java.security.Provider;

public class ExpathCrypto extends Provider {

	/**
	 * 
	 */
	private static final long serialVersionUID = -3274955405729286576L;
	private static String info = "SunJCE Provider "
			+ "(implements DES, Triple DES, Blowfish, PBE, Diffie-Hellman, HMAC-MD5, " + "HMAC-SHA1)";

	public ExpathCrypto() {
		/* We are the "base64" provider */
		super("ExpathCrypto", 1.4, info);

		AccessController.doPrivileged(new java.security.PrivilegedAction<Object>() {
			public Object run() {

				/*
				 * Cipher engines
				 */
				put("Cipher.DES", "com.sun.crypto.provider.DESCipher");
				put("Cipher.DESede", "com.sun.crypto.provider.DESedeCipher");
				put("Alg.Alias.Cipher.TripleDES", "DESede");
				put("Cipher.PBEWithMD5AndDES", "com.sun.crypto.provider.PBEWithMD5AndDESCipher");
				put("Cipher.PBEWithMD5AndTripleDES", "com.sun.crypto.provider.PBEWithMD5AndTripleDESCipher");
				put("Cipher.Blowfish", "com.sun.crypto.provider.BlowfishCipher");

				/*
				 * Key(pair) Generator engines
				 */
				put("KeyGenerator.DES", "com.sun.crypto.provider.DESKeyGenerator");

				put("KeyGenerator.DESede", "com.sun.crypto.provider.DESedeKeyGenerator");
				put("Alg.Alias.KeyGenerator.TripleDES", "DESede");

				put("KeyGenerator.Blowfish", "com.sun.crypto.provider.BlowfishKeyGenerator");

				put("KeyGenerator.HmacMD5", "com.sun.crypto.provider.HmacMD5KeyGenerator");

				put("KeyGenerator.HmacSHA1", "com.sun.crypto.provider.HmacSHA1KeyGenerator");

				put("KeyPairGenerator.DiffieHellman", "com.sun.crypto.provider.DHKeyPairGenerator");
				put("Alg.Alias.KeyPairGenerator.DH", "DiffieHellman");

				/*
				 * Algorithm parameter generation engines
				 */
				put("AlgorithmParameterGenerator.DiffieHellman", "com.sun.crypto.provider.DHParameterGenerator");
				put("Alg.Alias.AlgorithmParameterGenerator.DH", "DiffieHellman");

				/*
				 * Key Agreement engines
				 */
				put("KeyAgreement.DiffieHellman", "com.sun.crypto.provider.DHKeyAgreement");
				put("Alg.Alias.KeyAgreement.DH", "DiffieHellman");

				/*
				 * Algorithm Parameter engines
				 */
				put("AlgorithmParameters.DiffieHellman", "com.sun.crypto.provider.DHParameters");
				put("Alg.Alias.AlgorithmParameters.DH", "DiffieHellman");

				put("AlgorithmParameters.DES", "com.sun.crypto.provider.DESParameters");

				put("AlgorithmParameters.DESede", "com.sun.crypto.provider.DESedeParameters");
				put("Alg.Alias.AlgorithmParameters.TripleDES", "DESede");

				put("AlgorithmParameters.PBE", "com.sun.crypto.provider.PBEParameters");
				put("Alg.Alias.AlgorithmParameters.PBEWithMD5AndDES", "PBE");

				put("AlgorithmParameters.Blowfish", "com.sun.crypto.provider.BlowfishParameters");

				/*
				 * Key factories
				 */
				put("KeyFactory.DiffieHellman", "com.sun.crypto.provider.DHKeyFactory");
				put("Alg.Alias.KeyFactory.DH", "DiffieHellman");

				/*
				 * Secret-key factories
				 */
				put("SecretKeyFactory.DES", "com.sun.crypto.provider.DESKeyFactory");

				put("SecretKeyFactory.DESede", "com.sun.crypto.provider.DESedeKeyFactory");
				put("Alg.Alias.SecretKeyFactory.TripleDES", "DESede");

				put("SecretKeyFactory.PBEWithMD5AndDES", "com.sun.crypto.provider.PBEKeyFactory");

				/*
				 * MAC
				 */
				put("Mac.HmacMD5", "com.sun.crypto.provider.HmacMD5");
				put("Mac.HmacSHA1", "com.sun.crypto.provider.HmacSHA1");

				/*
				 * KeyStore
				 */
				put("KeyStore.JCEKS", "com.sun.crypto.provider.JceKeyStore");

				return null;
			}
		});
	}

}
