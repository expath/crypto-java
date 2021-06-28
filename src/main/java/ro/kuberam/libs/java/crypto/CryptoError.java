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

public enum CryptoError {
	
    NoSuchAlgorithmException("crypto:unknown-algorithm", "The specified algorithm is not supported."),
    SIGNATURE_TYPE("crypto:signature-type", "The specified signature type is not supported."),
    UNREADABLE_KEYSTORE("crypto:unreadable-keystore", "I/O error while reading keystore, or the password is incorrect."),
    DENIED_KEYSTORE("crypto:denied-keystore", "Permission denied to read keystore."),
    KEYSTORE_URL("crypto:keystore-url", "The keystore URL is invalid."),
    KeyStoreException("crypto:keystore-type", "The keystore type is not supported."),
    ALIAS_KEY("crypto:alias-key", "Cannot find key for alias in given keystore."),
    SIGNATURE_ELEMENT("crypto:signature-element", "Cannot find Signature element."),
    NoSuchPaddingException("crypto:inexistent-padding", "No such padding."),
    BadPaddingException("crypto:incorrect-padding", "Incorrect padding."),
    ENCRYPTION_TYPE("crypto:encryption-type", "The encryption type is not supported."),
    InvalidKeySpecException("crypto:invalid-crypto-key", "The cryptographic key is invalid."),
    InvalidKeyException("crypto:invalid-crypto-key", "The cryptographic key is invalid."),
    IllegalBlockSizeException("crypto:block-size", "Illegal block size."),
    DECRYPTION_TYPE("crypto:decryption-type", "The decryption type is not supported."),
    NoSuchProviderException("crypto:no-provider", "The provider is not set."),
    INPUT_RESOURCES("crypto.input-resources", "The 'enveloped' and 'enveloping' signatures have to be applied to only one resource."),
    INCORRECT_INITIALIZATION_VECTOR("crypto:incorrect-initialization-vector", "The initialization vector is not correct");

	private String code;
    private String message;

    CryptoError(String code, String message) {
    	this.code = code;
        this.message = message;
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
}
