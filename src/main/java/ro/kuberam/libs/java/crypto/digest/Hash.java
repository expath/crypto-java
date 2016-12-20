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

package ro.kuberam.libs.java.crypto.digest;

/**
 * Implements the crypto:hash() function.
 * 
 * @author Claudius Teodorescu <claudius.teodorescu@gmail.com>
 */

import java.io.BufferedInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.log4j.Logger;

import ro.kuberam.libs.java.crypto.ErrorMessages;
import java.util.Base64;

public class Hash {

	private final static Logger log = Logger.getLogger(Hash.class);

	public static String hashString(String data, String algorithm) throws Exception {
		return hashString(data, algorithm, "");
	}

	public static String hashString(String data, String algorithm, String format) throws Exception {

		// TODO: validate the format
		format = format.equals("") ? "base64" : format;

		MessageDigest messageDigester = getMessageDigester(algorithm);

		messageDigester.update(data.getBytes(StandardCharsets.UTF_8));

		byte[] resultBytes = messageDigester.digest();

		if (format.equals("base64")) {
			return Base64.getEncoder().encodeToString(resultBytes);
		} else {
			return convertToHex(resultBytes);
		}
	}

	public static String hashBinary(InputStream data, String algorithm) throws Exception {
		return hashBinary(data, algorithm, "");
	}

	public static String hashBinary(InputStream data, String algorithm, String format) throws Exception {

		// TODO: validate the format
		format = format.equals("") ? "base64" : format;

		String result = "";

		BufferedInputStream bis = new BufferedInputStream(data);
		MessageDigest messageDigester = getMessageDigester(algorithm);
		DigestInputStream dis = new DigestInputStream(bis, messageDigester);

		while (dis.read() != -1)
			;

		byte[] resultBytes = messageDigester.digest();

		if (format.equals("base64")) {
			result = Base64.getEncoder().encodeToString(resultBytes);
		} else {
			result = convertToHex(resultBytes);
		}

		log.info("hash value is: '" + result);

		return result;

		// byte[] buffer = new byte[bufferSize];
		// int sizeRead = -1;
		// while ((sizeRead = in.read(buffer)) != -1) {
		// digest.update(buffer, 0, sizeRead);
		// }
		// in.close();
		//
		// byte[] hash = null;
		// hash = new byte[digest.getDigestLength()];
		// hash = digest.digest();
	}

	private static MessageDigest getMessageDigester(String algorithm) throws Exception {
		MessageDigest messageDigester = null;

		try {
			messageDigester = MessageDigest.getInstance(algorithm);
		} catch (NoSuchAlgorithmException ex) {
			throw new Exception(ErrorMessages.error_unknownAlgorithm);
		}

		return messageDigester;
	}

	private static String convertToHex(byte[] data) {
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < data.length; i++) {
			int halfbyte = (data[i] >>> 4) & 0x0F;
			int two_halfs = 0;
			do {
				if ((0 <= halfbyte) && (halfbyte <= 9))
					buf.append((char) ('0' + halfbyte));
				else
					buf.append((char) ('a' + (halfbyte - 10)));
				halfbyte = data[i] & 0x0F;
			} while (two_halfs++ < 1);
		}
		return buf.toString();
	}
}