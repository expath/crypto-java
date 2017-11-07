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
package ro.kuberam.libs.java.crypto.digest;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ro.kuberam.libs.java.crypto.ErrorMessages;

import javax.annotation.Nullable;
import java.util.Base64;
import java.util.Optional;

/**
 * Implements the crypto:hash() function.
 *
 * @author Claudius Teodorescu <claudius.teodorescu@gmail.com>
 */
public class Hash {

    private static final Logger LOG = LogManager.getLogger(Hash.class);

    public static String hashString(final String data, final String algorithm) throws Exception {
        return hashString(data, algorithm, null);
    }

    public static String hashString(final String data, final String algorithm, final @Nullable String format) throws Exception {

        // TODO: validate the format
        final String actualFormat = Optional.ofNullable(format)
                .filter(str -> !str.isEmpty())
                .orElse("base64");    // default to Base64

        final MessageDigest messageDigester = getMessageDigester(algorithm);
        messageDigester.update(data.getBytes(StandardCharsets.UTF_8));

        final byte[] resultBytes = messageDigester.digest();

        if (actualFormat.equals("base64")) {
            return Base64.getEncoder().encodeToString(resultBytes);
        } else {
            return convertToHex(resultBytes);
        }
    }

    public static String hashBinary(final InputStream data, final String algorithm) throws Exception {
        return hashBinary(data, algorithm, null);
    }

    public static String hashBinary(final InputStream data, final String algorithm, @Nullable final String format) throws Exception {

        // TODO: validate the format
        final String actualFormat = Optional.ofNullable(format)
                .filter(str -> !str.isEmpty())
                .orElse("base64");    // default to Base64

        final byte[] resultBytes;
        final MessageDigest messageDigester = getMessageDigester(algorithm);

        final byte[] buf = new byte[16 * 1024]; // 16 KB
        int read = -1;
        while((read = data.read(buf)) > -1) {
            messageDigester.update(buf, 0, read);
        }
        resultBytes = messageDigester.digest();

        final String result;
        if (actualFormat.equals("base64")) {
            result = Base64.getEncoder().encodeToString(resultBytes);
        } else {
            result = convertToHex(resultBytes);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("hash value is: '" + result);
        }

        return result;
    }

    private static MessageDigest getMessageDigester(final String algorithm) throws Exception {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (final NoSuchAlgorithmException ex) {
            throw new Exception(ErrorMessages.error_unknownAlgorithm);
        }
    }

    private static String convertToHex(final byte[] data) {
        final StringBuilder buf = new StringBuilder();
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