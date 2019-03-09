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
package ro.kuberam.libs.java.crypto.digest;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import jakarta.xml.bind.DatatypeConverter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ro.kuberam.libs.java.crypto.CryptoException;
import ro.kuberam.libs.java.crypto.ExpathCryptoModule;
import ro.kuberam.libs.java.crypto.utils.Buffer;

public class Hmac {

	private static final Logger LOG = LoggerFactory.getLogger(Hmac.class);

	public static String hmac(final byte[] data, final byte[] secretKey, final String algorithm,
			@Nullable final String format) throws CryptoException {

		// TODO: validate the format
		final String actualFormat = Optional.ofNullable(format).filter(str -> !str.isEmpty()).orElse("base64");
		LOG.debug("secretKey = {}", secretKey);

		final byte[] resultBytes = hmac(data, secretKey, algorithm);

		final String result;
		if (actualFormat.equals("base64")) {
			result = Base64.getEncoder().encodeToString(resultBytes);
		} else {
			result = DatatypeConverter.printHexBinary(resultBytes).toLowerCase();
		}
		LOG.debug("result = {}", result);

		return result;
	}

	public static String hmac(final InputStream data, final byte[] secretKey, final String algorithm,
			@Nullable final String format) throws CryptoException, IOException {

		// TODO: validate the format
		String actualFormat = Optional.ofNullable(format).filter(str -> !str.isEmpty()).orElse("base64");
		LOG.debug("secretKey = {}", secretKey);

		byte[] resultBytes = hmac(data, secretKey, algorithm);

		String result;
		if (actualFormat.equals("base64")) {
			result = Base64.getEncoder().encodeToString(resultBytes);
		} else {
			result = DatatypeConverter.printHexBinary(resultBytes).toLowerCase();
		}
		LOG.debug("result = {}", result);

		return result;
	}

	public static byte[] hmac(final byte[] data, final byte[] secretKey, String algorithm) throws CryptoException {
		final Map<String, String> javaStandardAlgorithmNames = ExpathCryptoModule.javaStandardAlgorithmNames;

		if (javaStandardAlgorithmNames.containsKey(algorithm)) {
			algorithm = javaStandardAlgorithmNames.get(algorithm);
		}

		final SecretKeySpec signingKey = new SecretKeySpec(secretKey, algorithm);

		try {
			final Mac mac = Mac.getInstance(algorithm);
			mac.init(signingKey);
			return mac.doFinal(data);

		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new CryptoException(e);
		}
	}

	public static byte[] hmac(final InputStream data, final byte[] secretKey, String algorithm)
			throws CryptoException, IOException {
		final Map<String, String> javaStandardAlgorithmNames = ExpathCryptoModule.javaStandardAlgorithmNames;

		if (javaStandardAlgorithmNames.containsKey(algorithm)) {
			algorithm = javaStandardAlgorithmNames.get(algorithm);
		}

		final SecretKeySpec signingKey = new SecretKeySpec(secretKey, algorithm);

		try {
			Mac mac = Mac.getInstance(algorithm);
			mac.init(signingKey);

			byte[] buf = new byte[Buffer.TRANSFER_SIZE];
			int read = -1;
			while ((read = data.read(buf)) > -1) {
				mac.update(buf, 0, read);
			}

			return mac.doFinal();

		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new CryptoException(e);
		}
	}
}
