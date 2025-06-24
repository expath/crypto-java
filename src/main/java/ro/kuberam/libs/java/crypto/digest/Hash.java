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
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.annotation.Nullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ro.kuberam.libs.java.crypto.CryptoError;
import ro.kuberam.libs.java.crypto.CryptoException;
import ro.kuberam.libs.java.crypto.utils.Buffer;
import ro.kuberam.libs.java.crypto.utils.HexString;

/**
 * Implements the crypto:hash() function.
 *
 * @author <a href="mailto:claudius.teodorescu@gmail.com">Claudius
 *         Teodorescu</a>
 */
public class Hash {

	private static final Logger LOG = LoggerFactory.getLogger(Hash.class);

	public static String hashString(final String data, final String algorithm) throws CryptoException {
		return hashString(data, algorithm, null, null);
	}

	public static String hashString(final String data, final String algorithm, @Nullable final String provider) throws CryptoException {
		return hashString(data, algorithm, provider, null);
	}

	public static String hashString(final String data, final String algorithm, @Nullable final String provider, final @Nullable String format)
			throws CryptoException {

		// TODO: validate the format
		final String actualFormat = Optional.ofNullable(format).filter(str -> !str.isEmpty()).orElse("base64");

		final MessageDigest messageDigester = getMessageDigester(algorithm, provider);
		messageDigester.update(data.getBytes(StandardCharsets.UTF_8));

		final byte[] resultBytes = messageDigester.digest();

		if (actualFormat.equals("base64")) {
			return Base64.getEncoder().encodeToString(resultBytes);
		} else {
			return HexString.fromBytes(resultBytes);
		}
	}

	public static String hashBinary(final InputStream data, final String algorithm)
			throws CryptoException, IOException {
		return hashBinary(data, algorithm, null, null);
	}

	public static String hashBinary(final InputStream data, final String algorithm, @Nullable final String provider)
			throws CryptoException, IOException {
		return hashBinary(data, algorithm, provider, null);
	}

	public static String hashBinary(final InputStream data, final String algorithm, @Nullable final String provider, @Nullable final String format)
			throws CryptoException, IOException {

		// TODO: validate the format
		final String actualFormat = Optional.ofNullable(format).filter(str -> !str.isEmpty()).orElse("base64");

		final byte[] resultBytes;
		final MessageDigest messageDigester = getMessageDigester(algorithm, provider);

		final byte[] buf = new byte[Buffer.TRANSFER_SIZE];
		int read = -1;
		while ((read = data.read(buf)) > -1) {
			messageDigester.update(buf, 0, read);
		}
		resultBytes = messageDigester.digest();

		final String result;
		if (actualFormat.equals("base64")) {
			result = Base64.getEncoder().encodeToString(resultBytes);
		} else {
			result = HexString.fromBytes(resultBytes);
		}
		LOG.debug("hash value is = {}", result);

		return result;
	}

	private static MessageDigest getMessageDigester(final String algorithm, @Nullable final String provider) throws CryptoException {
		try {
			if (provider != null) {
				return MessageDigest.getInstance(algorithm, provider);
			} else {
				return MessageDigest.getInstance(algorithm);
			}
		} catch (final NoSuchAlgorithmException e) {
			throw new CryptoException(CryptoError.UNKNOWN_ALGORITHM, e);
		} catch (final NoSuchProviderException e) {
			throw new CryptoException(CryptoError.UNKNOWN_PROVIDER, e);
		}
	}

	/**
	 * Returns a list of security providers which
	 * offer hash services.
	 *
	 * @return the names of the security providers which
	 *     offer hash services.
	 */
	public static List<String> listProviders() {
		final List<String> hashProviders = new ArrayList<>();

		final Provider[] providers = Security.getProviders();
		for (final Provider provider : providers) {
			final Set<Provider.Service> services = provider.getServices();
			for (final Provider.Service service : services) {
				if (service.getType().equals("MessageDigest")) {
					hashProviders.add(provider.getName());
					break;
				}
			}
		}

		return hashProviders;
	}

	/**
	 * Returns a Map of all hash services from each
	 * security provider.
	 *
	 * @return a map from key: `service provider name` to value: `algorithm name(s)`.
	 */
	public static Map<String, Set<String>> listAlgorithms() {
		final Map<String, Set<String>> algorithms = new HashMap<>();

		final Provider[] providers = Security.getProviders();
		for (final Provider provider : providers) {
			final Set<Provider.Service> services = provider.getServices();
			for (final Provider.Service service : services) {
				if (service.getType().equals("MessageDigest")) {

					final Set<String> providerAlgs = algorithms.computeIfAbsent(provider.getName(), k -> new HashSet<>());
					providerAlgs.add(service.getAlgorithm());
				}
			}
		}

		return algorithms;
	}

	/**
	 * Returns a Map of all hash services from a
	 * security provider.
	 *
	 * @param providerName the name of the security provider.
	 *
	 * @return the names of the algorithms provided by the security provider.
	 */
	public static Set<String> listAlgorithms(final String providerName) {
		final Set<String> algorithms = new HashSet<>();

		final Provider provider = Security.getProvider(providerName);
		final Set<Provider.Service> services = provider.getServices();
		for (final Provider.Service service : services) {
			if (service.getType().equals("MessageDigest")) {
				algorithms.add(service.getAlgorithm());
			}
		}

		return algorithms;
	}
}
