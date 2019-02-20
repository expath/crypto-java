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
package ro.kuberam.libs.java.crypto.encrypt;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.StringTokenizer;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import ro.kuberam.libs.java.crypto.CryptoException;
import ro.kuberam.libs.java.crypto.utils.Buffer;

/**
 * @author <a href="mailto:claudius.teodorescu@gmail.com">Claudius
 *         Teodorescu</a>
 */
public class AsymmetricEncryption {

	public static String encryptString(String data, String base64PublicKey, String transformationName)
			throws CryptoException, IOException {
		String provider = "SUN";

		return encryptString(data, base64PublicKey, transformationName, provider);
	}

	public static String encryptString(String data, String base64PublicKey, String transformationName, String provider)
			throws CryptoException, IOException {
		byte[] dataBytes = data.getBytes(UTF_8);
		String algorithm = transformationName.split("/")[0];
		byte[] resultBytes = null;

		Cipher cipher;
		try {
			cipher = Cipher.getInstance(transformationName);
			PublicKey publicKey = loadPublicKey(base64PublicKey, algorithm, provider);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			resultBytes = cipher.doFinal(dataBytes);
		} catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidKeyException e) {
			throw new CryptoException(e);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return Base64.getEncoder().encodeToString(resultBytes);
	}

	public static String decryptString(String encryptedData, String base64PrivateKey, String transformationName)
			throws CryptoException, IOException {
		String provider = "SUN";

		return decryptString(encryptedData, base64PrivateKey, transformationName, provider);
	}

	public static String decryptString(String encryptedData, String base64PrivateKey, String transformationName,
			String provider) throws CryptoException, IOException {
		byte[] dataBytes = Base64.getDecoder().decode(encryptedData);
		String algorithm = transformationName.split("/")[0];
		byte[] resultBytes = null;

		Cipher cipher;
		try {
			cipher = Cipher.getInstance(transformationName);
			cipher.init(Cipher.DECRYPT_MODE, loadPrivateKey(base64PrivateKey, algorithm, provider));
			resultBytes = cipher.doFinal(dataBytes);
		} catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidKeyException e) {
			throw new CryptoException(e);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return new String(resultBytes, UTF_8);
	}

	public static String encryptBinary(InputStream data, String base64PublicKey, String transformationName,
			String provider) throws CryptoException, IOException {
		String algorithm = transformationName.split("/")[0];
		byte[] resultBytes = null;

		Cipher cipher;
		try {
			cipher = Cipher.getInstance(transformationName);
			PublicKey publicKey = loadPublicKey(base64PublicKey, algorithm, provider);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);

			byte[] buf = new byte[Buffer.TRANSFER_SIZE];
			int read = -1;
			while ((read = data.read(buf)) > -1) {
				cipher.update(buf, 0, read);
			}
			resultBytes = cipher.doFinal();
		} catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidKeyException e) {
			throw new CryptoException(e);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return getString(resultBytes);
	}

	public static String decryptBinary(InputStream data, String base64PrivateKey, String transformationName,
			String provider) throws CryptoException, IOException {
		String algorithm = transformationName.split("/")[0];
		byte[] resultBytes = null;

		Cipher cipher;
		try {
			cipher = Cipher.getInstance(transformationName);
			PrivateKey privateKey = loadPrivateKey(base64PrivateKey, algorithm, provider);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);

			byte[] buf = new byte[Buffer.TRANSFER_SIZE];
			int read = -1;
			while ((read = data.read(buf)) > -1) {
				cipher.update(buf, 0, read);
			}
			resultBytes = cipher.doFinal();
		} catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidKeyException e) {
			throw new CryptoException(e);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return getString(resultBytes);
	}

	public static String getString(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < bytes.length; i++) {
			byte b = bytes[i];
			sb.append((int) (0x00FF & b));
			if (i + 1 < bytes.length) {
				sb.append("-");
			}
		}
		return sb.toString();
	}

	public static byte[] getBytes(String str) throws IOException {
		StringTokenizer st = new StringTokenizer(str, "-", false);
		try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
			while (st.hasMoreTokens()) {
				int i = Integer.parseInt(st.nextToken());
				bos.write((byte) i);
			}
			return bos.toByteArray();
		}
	}

	private static PublicKey loadPublicKey(String base64PublicKey, String algorithm, String provider)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		// provider = Optional.ofNullable(provider).filter(str ->
		// !str.isEmpty()).orElse("SunRsaSign");
		provider = "SunRsaSign";

		X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes(UTF_8)));
		KeyFactory kf = KeyFactory.getInstance(algorithm, provider);

		return kf.generatePublic(spec);
	}

	private static PrivateKey loadPrivateKey(String base64PrivateKey, String algorithm, String provider)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		// provider = Optional.ofNullable(provider).filter(str ->
		// !str.isEmpty()).orElse("SunRsaSign");
		provider = "SunRsaSign";

		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(
				Base64.getDecoder().decode(base64PrivateKey.getBytes(UTF_8)));

		KeyFactory kf = KeyFactory.getInstance(algorithm, provider);

		return kf.generatePrivate(keySpec);
	}
}
