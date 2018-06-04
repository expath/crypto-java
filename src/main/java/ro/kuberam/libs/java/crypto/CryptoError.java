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
package ro.kuberam.libs.java.crypto;

public enum CryptoError {

    UNKNOWN_ALGORITH("The specified algorithm is not supported"),
    SIGNATURE_TYPE("The specified signature type is not supported."),
    UNREADABLE_KEYSTORE("I/O error while reading keystore, or the password is incorrect."),
    DENIED_KEYSTORE("Permission denied to read keystore."),
    KEYSTORE_URL("The keystore URL is invalid."),
    KEYSTORE_TYPE("The keystore type is not supported."),
    ALIAS_KEY("Cannot find key for alias in given keystore."),
    INVALID_KEY("The specified key is invalid."),
    SIGNATURE_ELEMENT("Cannot find Signature element."),
    INEXISTENT_PADDING("No such padding."),
    INCORRECT_PADDING("Incorrect padding."),
    ENCRYPTION_TYPE("The encryption type is not supported."),
    INVALID_CRYPTO_KEY("The cryptographic key is invalid."),
    BLOCK_SIZE("Illegal block size."),
    DECRYPTION_TYPE("The decryption type is not supported."),
    NO_PROVIDER("The provider is not set."),
    OUTPUT_FORMAT("The output format is not supported.");

    private final String description;

    CryptoError(final String description) {
        this.description = description;
    }

    public String asMessage() {
        return asMessage("crypto");
    }

    public String asMessage(final String nsPrefix) {
        return nsPrefix + ':' + name().toLowerCase().replace('_', '-') + ": " + description;
    }
}