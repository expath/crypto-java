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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
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

import ro.kuberam.libs.java.crypto.CryptoError;
import ro.kuberam.libs.java.crypto.CryptoException;
import ro.kuberam.libs.java.crypto.utils.Buffer;

import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * @author <a href="mailto:claudius.teodorescu@gmail.com">Claudius Teodorescu</a>
 */
public class AsymmetricEncryption {

    public static String encryptString(final String input, final String publicKey, final String transformationName)
            throws CryptoException, IOException {
        try (final InputStream bais = new ByteArrayInputStream(input.getBytes(UTF_8))) {
            return encrypt(bais, publicKey, transformationName);
        }
    }

    public static String encrypt(final InputStream input, final String publicKey, final String transformationName)
            throws CryptoException, IOException {
        final String algorithm = (transformationName.contains("/"))
                ? transformationName.substring(0, transformationName.indexOf("/")) : transformationName;

        final Cipher cipher;
        try {
            cipher = Cipher.getInstance(transformationName);
        } catch (final NoSuchAlgorithmException e) {
            throw new CryptoException(CryptoError.UNKNOWN_ALGORITH, e);
        } catch (final NoSuchPaddingException e) {
            throw new CryptoException(CryptoError.INEXISTENT_PADDING, e);
        }

        final X509EncodedKeySpec publicKeySpecification = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));

        try {
            final PublicKey publicKey1 = KeyFactory.getInstance(algorithm).generatePublic(publicKeySpecification);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey1);
        } catch (final NoSuchAlgorithmException e) {
            throw new CryptoException(CryptoError.UNKNOWN_ALGORITH, e);
        } catch (final InvalidKeyException | InvalidKeySpecException e) {
            throw new CryptoException(CryptoError.INVALID_CRYPTO_KEY, e);
        }

        final byte[] resultBytes;
        try {
            final byte[] buf = new byte[Buffer.TRANSFER_SIZE];
            int read = -1;
            while((read = input.read(buf)) > -1) {
                cipher.update(buf, 0, read);
            }
            resultBytes = cipher.doFinal();
        } catch (final IllegalBlockSizeException e) {
            throw new CryptoException(CryptoError.BLOCK_SIZE, e);
        } catch (final BadPaddingException e) {
            throw new CryptoException(CryptoError.INCORRECT_PADDING, e);
        }

        return getString(resultBytes);
    }

    public static String decryptString(final String encryptedInput, final String plainKey,
            final String transformationName, final String iv, @Nullable final String provider) throws CryptoException, IOException {
        try (final InputStream bais = new ByteArrayInputStream(getBytes(encryptedInput))) {
            return decrypt(bais, plainKey, transformationName, iv, provider);
        }
    }

    public static String decrypt(final InputStream encryptedInput, final String plainKey,
            final String transformationName, final String iv, @Nullable final String provider) throws CryptoException, IOException {
        final String algorithm = (transformationName.contains("/"))
                ? transformationName.substring(0, transformationName.indexOf("/")) : transformationName;

        final String actualProvider = Optional.ofNullable(provider)
                .filter(str -> !str.isEmpty())
                .orElse("SunJCE");    // default to SunJCE

        final Cipher cipher;
        try {
            cipher = Cipher.getInstance(transformationName, actualProvider);
        } catch (final NoSuchProviderException e) {
            throw new CryptoException(CryptoError.NO_PROVIDER, e);
        } catch (final NoSuchAlgorithmException e) {
            throw new CryptoException(CryptoError.UNKNOWN_ALGORITH, e);
        } catch (final NoSuchPaddingException e) {
            throw new CryptoException(CryptoError.INEXISTENT_PADDING, e);
        }

        final SecretKeySpec skeySpec = new SecretKeySpec(plainKey.getBytes(UTF_8), algorithm);
        if (transformationName.contains("/")) {
            final IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes(UTF_8), 0, 16);
            try {
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
            } catch (final InvalidAlgorithmParameterException e) {
                throw new CryptoException(CryptoError.UNKNOWN_ALGORITH, e);
            } catch (final InvalidKeyException e) {
                throw new CryptoException(CryptoError.INVALID_CRYPTO_KEY, e);
            }
        } else {
            try {
                cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            } catch (final InvalidKeyException e) {
                throw new CryptoException(CryptoError.INVALID_CRYPTO_KEY, e);
            }
        }

        try {
            final byte[] buf = new byte[Buffer.TRANSFER_SIZE];
            int read = -1;
            while((read = encryptedInput.read(buf)) > -1) {
                cipher.update(buf, 0, read);
            }

            final byte[] resultBytes = cipher.doFinal();
            return new String(resultBytes, UTF_8);
        } catch (final IllegalBlockSizeException e) {
            throw new CryptoException(CryptoError.BLOCK_SIZE, e);
        } catch (final BadPaddingException e) {
            throw new CryptoException(CryptoError.INCORRECT_PADDING, e);
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
