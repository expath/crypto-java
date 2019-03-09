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
package ro.kuberam.libs.java.crypto;

import javax.annotation.Nullable;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

public enum CryptoError {
	
    UNKNOWN_ALGORITHM("crypto:unknown-algorithm", "The specified algorithm is not supported.", NoSuchAlgorithmException.class),
    UNKNOWN_PROVIDER("crypto:unknown-provider", "The specified provider is not available."),
    SIGNATURE_TYPE("crypto:signature-type", "The specified signature type is not supported."),
    UNREADABLE_KEYSTORE("crypto:unreadable-keystore", "I/O error while reading keystore, or the password is incorrect."),
    DENIED_KEYSTORE("crypto:denied-keystore", "Permission denied to read keystore."),
    KEYSTORE_URL("crypto:keystore-url", "The keystore URL is invalid."),
    KEYSTORE_TYPE("crypto:keystore-type", "The keystore type is not supported.", KeyStoreException.class),
    ALIAS_KEY("crypto:alias-key", "Cannot find key for alias in given keystore."),
    SIGNATURE_ELEMENT("crypto:signature-element", "Cannot find Signature element."),
    INEXISTENT_PADDING("crypto:inexistent-padding", "No such padding.", NoSuchPaddingException.class),
    INCORRECT_PADDING("crypto:incorrect-padding", "Incorrect padding.", BadPaddingException.class),
    ENCRYPTION_TYPE("crypto:encryption-type", "The encryption type is not supported."),
    INVALID_CRYPTO_KEY("crypto:invalid-crypto-key", "The cryptographic key is invalid.", InvalidKeySpecException.class, InvalidKeyException.class),
    BLOCK_SIZE("crypto:block-size", "Illegal block size.", IllegalBlockSizeException.class),
    DECRYPTION_TYPE("crypto:decryption-type", "The decryption type is not supported."),
    NO_PROVIDER("crypto:no-provider", "The provider is not set.", NoSuchProviderException.class),
    INPUT_RESOURCES("crypto.input-resources", "The 'enveloped' and 'enveloping' signatures have to be applied to only one resource."),
    INCORRECT_INITIALIZATION_VECTOR("crypto:incorrect-initialization-vector", "The initialization vector is not correct");

	private final String code;
    private final String message;
    @Nullable final Class<? extends Throwable>[] describesExceptions;

    CryptoError(final String code, final String message) {
        this(code, message, null);
    }

    CryptoError(final String code, final String message, @Nullable final Class<? extends Throwable>... describesExceptions) {
    	this.code = code;
        this.message = message;
        this.describesExceptions = describesExceptions;
    }

    public String getCode() {
        return this.code;
    }
    
    public String getMessage() {
        return this.message;
    }
    
    public String getDescription() {
        return this.code + ", " + this.message;
    }

    public static @Nullable CryptoError describeException(@Nullable final Throwable t) {
        if (t == null) {
            return null;
        }

        for (final CryptoError cryptoError : values()) {
            if (cryptoError.describesExceptions != null) {
                for (final Class<? extends Throwable> describesException : cryptoError.describesExceptions) {
                    if (describesException == t.getClass()) {
                        return cryptoError;
                    }
                }
            }
        }

        return null;
    }
}
