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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Optional;
import java.util.StringTokenizer;

import javax.annotation.Nullable;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import ro.kuberam.libs.java.crypto.ErrorMessages;

import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * @author Claudius Teodorescu <claudius.teodorescu@gmail.com>
 */
public class AsymmetricEncryption {

    public static String encryptString(final String input, final String publicKey, final String transformationName) throws Exception {
        final String algorithm = (transformationName.contains("/"))
                ? transformationName.substring(0, transformationName.indexOf("/")) : transformationName;

        final Cipher cipher;
        try {
            cipher = Cipher.getInstance(transformationName);
        } catch (final NoSuchAlgorithmException ex) {
            throw new Exception(ErrorMessages.error_unknownAlgorithm);
        } catch (final NoSuchPaddingException ex) {
            throw new Exception(ErrorMessages.error_noPadding);
        }

        final X509EncodedKeySpec publicKeySpecification = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
        final PublicKey publicKey1 = KeyFactory.getInstance(algorithm).generatePublic(publicKeySpecification);

        try {
            cipher.init(Cipher.ENCRYPT_MODE, publicKey1);
        } catch (final InvalidKeyException ex) {
            throw new Exception(ErrorMessages.error_cryptoKey);
        }

        final byte[] resultBytes;
        try {
            resultBytes = cipher.doFinal(input.getBytes());
        } catch (final IllegalBlockSizeException ex) {
            throw new Exception(ErrorMessages.error_blockSize);
        } catch (final BadPaddingException ex) {
            throw new Exception(ErrorMessages.error_incorrectPadding);
        }

        return getString(resultBytes);
    }

    public static String decryptString(final String encryptedInput, final String plainKey, final String transformationName, final String iv,
                                       @Nullable final String provider) throws Exception {
        final String algorithm = (transformationName.contains("/"))
                ? transformationName.substring(0, transformationName.indexOf("/")) : transformationName;

        final String actualProvider = Optional.ofNullable(provider)
                .filter(str -> !str.isEmpty())
                .orElse("SunJCE");    // default to SunJCE

        final Cipher cipher;
        try {
            cipher = Cipher.getInstance(transformationName, actualProvider);
        } catch (final NoSuchAlgorithmException ex) {
            throw new Exception(ErrorMessages.error_unknownAlgorithm);
        } catch (final NoSuchPaddingException ex) {
            throw new Exception(ErrorMessages.error_noPadding);
        }

        final SecretKeySpec skeySpec = new SecretKeySpec(plainKey.getBytes(UTF_8), algorithm);
        if (transformationName.contains("/")) {
            final IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes(UTF_8), 0, 16);
            try {
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
            } catch (final InvalidKeyException ex) {
                throw new Exception(ErrorMessages.error_cryptoKey);
            }
        } else {
            try {
                cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            } catch (final InvalidKeyException ex) {
                throw new Exception(ErrorMessages.error_cryptoKey);
            }
        }

        try {
            final byte[] resultBytes = cipher.doFinal(getBytes(encryptedInput));
            return new String(resultBytes, UTF_8);
        } catch (final IllegalBlockSizeException ex) {
            throw new Exception(ErrorMessages.error_blockSize);
        } catch (final BadPaddingException ex) {
            throw new Exception(ErrorMessages.error_incorrectPadding);
        }
    }

    public static String getString(final byte[] bytes) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            final byte b = bytes[i];
            sb.append((int) (0x00FF & b));
            if (i + 1 < bytes.length) {
                sb.append("-");
            }
        }
        return sb.toString();
    }

    public static byte[] getBytes(final String str) throws IOException {
        final StringTokenizer st = new StringTokenizer(str, "-", false);
        try (final ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            while (st.hasMoreTokens()) {
                final int i = Integer.parseInt(st.nextToken());
                bos.write((byte) i);
            }
            return bos.toByteArray();
        }
    }

}
