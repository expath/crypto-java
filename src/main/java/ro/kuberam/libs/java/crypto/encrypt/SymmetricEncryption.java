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
package ro.kuberam.libs.java.crypto.encrypt;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import ro.kuberam.libs.java.crypto.CryptoError;
import ro.kuberam.libs.java.crypto.CryptoException;

/**
 * @author <a href="mailto:claudius.teodorescu@gmail.com">Claudius
 *         Teodorescu</a>
 */
public class SymmetricEncryption {

	public static byte[] encrypt(byte[] input, String plainKey, String transformationName, String iv, String provider)
			throws CryptoException, IOException {
		return operation(input, plainKey, transformationName, iv, provider, Cipher.ENCRYPT_MODE);
	}

	public static byte[] decrypt(byte[] encryptedInput, final String plainKey, final String transformationName,
			final String iv, final String provider) throws CryptoException, IOException {
		return operation(encryptedInput, plainKey, transformationName, iv, provider, Cipher.DECRYPT_MODE);
	}

	public static byte[] operation(byte[] input, String secretKey, String transformationName, String iv,
			String provider, int operationType) throws CryptoException, IOException {
		String algorithm = (transformationName.contains("/"))
				? transformationName.substring(0, transformationName.indexOf("/"))
				: transformationName;
		String actualProvider = Optional.ofNullable(provider).filter(str -> !str.isEmpty()).orElse("SunJCE");
		Cipher cipher;
		byte[] result;

		try {
			cipher = Cipher.getInstance(transformationName, actualProvider);
		} catch (NoSuchProviderException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new CryptoException(e);
		}

		SecretKeySpec skeySpec = generateSecretKey(secretKey, algorithm);
		if (transformationName.contains("/")) {
			final IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes(UTF_8), 0, 16);
			try {
				cipher.init(operationType, skeySpec, ivSpec);
			} catch (InvalidAlgorithmParameterException | InvalidKeyException e) {
				throw new CryptoException(e);
			}
		} else {
			try {
				cipher.init(operationType, skeySpec);
			} catch (InvalidKeyException e) {
				throw new CryptoException(CryptoError.INVALID_CRYPTO_KEY, e);
			}
		}

		try {
			result = cipher.doFinal(input);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new CryptoException(e);
		}

		return result;
	}

	private static SecretKeySpec generateSecretKey(String secretKey, String algorithm) {
		return new SecretKeySpec(secretKey.getBytes(UTF_8), algorithm);
	}

}

// import java.security.NoSuchAlgorithmException;
// import java.security.SecureRandom;
// import java.security.spec.InvalidKeySpecException;
// import java.security.spec.KeySpec;
// import java.util.Arrays;
//
// import javax.crypto.SecretKeyFactory;
// import javax.crypto.spec.PBEKeySpec;
//
// public class PasswordEncryptionService {
//
// public boolean authenticate(String attemptedPassword, byte[]
// encryptedPassword, byte[] salt)
// throws NoSuchAlgorithmException, InvalidKeySpecException {
// // Encrypt the clear-text password using the same salt that was used to
// // encrypt the original password
// byte[] encryptedAttemptedPassword = getEncryptedPassword(attemptedPassword,
// salt);
//
// // Authentication succeeds if encrypted password that the user entered
// // is equal to the stored hash
// return Arrays.equals(encryptedPassword, encryptedAttemptedPassword);
// }
//
// public byte[] getEncryptedPassword(String password, byte[] salt)
// throws NoSuchAlgorithmException, InvalidKeySpecException {
// // PBKDF2 with SHA-1 as the hashing algorithm. Note that the NIST
// // specifically names SHA-1 as an acceptable hashing algorithm for PBKDF2
// String algorithm = "PBKDF2WithHmacSHA1";
// // SHA-1 generates 160 bit hashes, so that's what makes sense here
// int derivedKeyLength = 160;
// // Pick an iteration count that works for you. The NIST recommends at
// // least 1,000 iterations:
// // http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf
// // iOS 4.x reportedly uses 10,000:
// //
// http://blog.crackpassword.com/2010/09/smartphone-forensics-cracking-blackberry-backup-passwords/
// int iterations = 20000;
//
// KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations,
// derivedKeyLength);
//
// SecretKeyFactory f = SecretKeyFactory.getInstance(algorithm);
//
// return f.generateSecret(spec).getEncoded();
// }
//
// public byte[] generateSalt() throws NoSuchAlgorithmException {
// // VERY important to use SecureRandom instead of just Random
// SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
//
// // Generate a 8 byte (64 bit) salt as recommended by RSA PKCS5
// byte[] salt = new byte[8];
// random.nextBytes(salt);
//
// return salt;
// }
// }
