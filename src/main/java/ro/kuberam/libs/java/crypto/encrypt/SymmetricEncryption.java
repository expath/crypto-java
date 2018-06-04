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
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;
import java.util.StringTokenizer;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import ro.kuberam.libs.java.crypto.ErrorMessages;
import ro.kuberam.libs.java.crypto.utils.Buffer;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * @author <a href="mailto:claudius.teodorescu@gmail.com">Claudius Teodorescu</a>
 */
public class SymmetricEncryption {

    public static String encryptString(final String input, final String plainKey, final String transformationName,
            final String iv, final String provider) throws Exception {
        try (final InputStream bais = new ByteArrayInputStream(input.getBytes(UTF_8))) {
            return encrypt(bais, plainKey, transformationName, iv, provider);
        }
    }

    public static String encrypt(final InputStream input, final String plainKey, final String transformationName,
            final String iv, final String provider) throws Exception {
        final String algorithm = (transformationName.contains("/")) ? transformationName.substring(0, transformationName.indexOf("/")) : transformationName;
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
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
            } catch (InvalidKeyException ex) {
                throw new Exception(ErrorMessages.error_cryptoKey);
            }
        } else {
            try {
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
            } catch (final InvalidKeyException ex) {
                throw new Exception(ErrorMessages.error_cryptoKey);
            }
        }

        try {
            final byte[] buf = new byte[Buffer.TRANSFER_SIZE];
            int read = -1;
            while((read = input.read(buf)) > -1) {
                cipher.update(buf, 0, read);
            }

            final byte[] resultBytes = cipher.doFinal();
            return getString(resultBytes);
        } catch (final IllegalBlockSizeException ex) {
            throw new Exception(ErrorMessages.error_blockSize);
        } catch (final BadPaddingException ex) {
            throw new Exception(ErrorMessages.error_incorrectPadding);
        }
    }

    public static String decryptString(final String encryptedInput, final String plainKey,
            final String transformationName, final String iv, final String provider) throws Exception {
        try (final InputStream bais = new ByteArrayInputStream(getBytes(encryptedInput))) {
            return decrypt(bais, plainKey, transformationName, iv, provider);
        }
    }

    public static String decrypt(final InputStream encryptedInput, final String plainKey,
            final String transformationName, final String iv, final String provider) throws Exception {
        final String algorithm = (transformationName.contains("/")) ? transformationName.substring(0, transformationName.indexOf("/")) : transformationName;
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

        final SecretKeySpec skeySpec = new SecretKeySpec(plainKey.getBytes(StandardCharsets.UTF_8), algorithm);
        if (transformationName.contains("/")) {
            final IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8), 0, 16);
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

            final byte[] buf = new byte[Buffer.TRANSFER_SIZE];
            int read = -1;
            while((read = encryptedInput.read(buf)) > -1) {
                cipher.update(buf, 0, read);
            }

            final byte[] resultBytes = cipher.doFinal();
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
