/*
 *  Copyright (C) 2011 Claudius Teodorescu
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 *  $Id$
 */

package ro.kuberam.libs.java.crypto.encrypt;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.StringTokenizer;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import ro.kuberam.libs.java.crypto.ErrorMessages;

/**
 * 
 * @author Claudius Teodorescu <claudius.teodorescu@gmail.com>
 */
public class SymmetricEncryption {

	public static String encryptString(String input, String plainKey, String transformationName, String iv, String provider) throws Exception {

		IvParameterSpec ivSpec = null;
		String algorithm = (transformationName.contains("/")) ? transformationName.substring(0, transformationName.indexOf("/")) : transformationName;
		provider = provider.equals("") ? "SunJCE" : provider;
		Cipher cipher = null;

		try {
			cipher = Cipher.getInstance(transformationName, provider);
		} catch (NoSuchAlgorithmException ex) {
			throw new Exception(ErrorMessages.error_unknownAlgorithm);
		} catch (NoSuchPaddingException ex) {
			throw new Exception(ErrorMessages.error_noPadding);
		}

		SecretKeySpec skeySpec = new SecretKeySpec(plainKey.getBytes("UTF-8"), algorithm);

		if (transformationName.contains("/")) {
			ivSpec = new IvParameterSpec(iv.getBytes("UTF-8"), 0, 16);
			try {
				cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
			} catch (InvalidKeyException ex) {
				throw new Exception(ErrorMessages.error_cryptoKey);
			}
		} else {
			try {
				cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
			} catch (InvalidKeyException ex) {
				throw new Exception(ErrorMessages.error_cryptoKey);
			}
		}

		byte[] resultBytes = null;
		try {
			resultBytes = cipher.doFinal(input.getBytes());
		} catch (IllegalBlockSizeException ex) {
			throw new Exception(ErrorMessages.error_blockSize);
		} catch (BadPaddingException ex) {
			throw new Exception(ErrorMessages.error_incorrectPadding);
		}

		return getString(resultBytes);
	}

	public static String decryptString(String encryptedInput, String plainKey, String transformationName, String iv, String provider) throws Exception {

		IvParameterSpec ivSpec = null;
		String algorithm = (transformationName.contains("/")) ? transformationName.substring(0, transformationName.indexOf("/")) : transformationName;
		provider = provider.equals("") ? "SunJCE" : provider;
		Cipher cipher = null;

		try {
			cipher = Cipher.getInstance(transformationName, provider);
		} catch (NoSuchAlgorithmException ex) {
			throw new Exception(ErrorMessages.error_unknownAlgorithm);
		} catch (NoSuchPaddingException ex) {
			throw new Exception(ErrorMessages.error_noPadding);
		}

		SecretKeySpec skeySpec = new SecretKeySpec(plainKey.getBytes("UTF-8"), algorithm);

		if (transformationName.contains("/")) {
			ivSpec = new IvParameterSpec(iv.getBytes("UTF-8"), 0, 16);
			try {
				cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
			} catch (InvalidKeyException ex) {
				throw new Exception(ErrorMessages.error_cryptoKey);
			}
		} else {
			try {
				cipher.init(Cipher.DECRYPT_MODE, skeySpec);
			} catch (InvalidKeyException ex) {
				throw new Exception(ErrorMessages.error_cryptoKey);
			}
		}

		byte[] resultBytes = null;
		try {
			resultBytes = cipher.doFinal(getBytes(encryptedInput));
		} catch (IllegalBlockSizeException ex) {
			throw new Exception(ErrorMessages.error_blockSize);
		} catch (BadPaddingException ex) {
			throw new Exception(ErrorMessages.error_incorrectPadding);
		}

		return new String(resultBytes);
	}

	public static String getString(byte[] bytes) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < bytes.length; i++) {
			byte b = bytes[i];
			sb.append((int) (0x00FF & b));
			if (i + 1 < bytes.length) {
				sb.append("-");
			}
		}
		return sb.toString();
	}

	public static byte[] getBytes(String str) {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		StringTokenizer st = new StringTokenizer(str, "-", false);
		while (st.hasMoreTokens()) {
			int i = Integer.parseInt(st.nextToken());
			bos.write((byte) i);
		}
		return bos.toByteArray();
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
