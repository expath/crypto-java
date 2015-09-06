/*
 *  Copyright (C) 2015 Claudius Teodorescu
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
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.X509EncodedKeySpec;
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
public class AsymmetricEncryption {

	public static String encryptString(String input, String publicKey, String algorithm) throws Exception {

		Cipher cipher = null;

		try {
			cipher = Cipher.getInstance(algorithm);
		} catch (NoSuchAlgorithmException ex) {
			throw new Exception(ErrorMessages.error_unknownAlgorithm);
		} catch (NoSuchPaddingException ex) {
			throw new Exception(ErrorMessages.error_noPadding);
		}

		X509EncodedKeySpec publicKeySpecification = new X509EncodedKeySpec(publicKey.getBytes("UTF-8"));
		
		try {
			cipher.init(Cipher.ENCRYPT_MODE, KeyFactory.getInstance("RSA").generatePublic(publicKeySpecification));
		} catch (InvalidKeyException ex) {
			throw new Exception(ErrorMessages.error_cryptoKey);
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

	public static String decryptString(String encryptedInput, String plainKey, String transformationName,
			String iv, String provider) throws Exception {

		IvParameterSpec ivSpec = null;
		String algorithm = (transformationName.contains("/")) ? transformationName.substring(0,
				transformationName.indexOf("/")) : transformationName;
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
