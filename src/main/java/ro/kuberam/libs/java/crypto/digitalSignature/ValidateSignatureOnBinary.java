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
package ro.kuberam.libs.java.crypto.digitalSignature;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import ro.kuberam.libs.java.crypto.keyManagement.GenerateKeyPair;

public class ValidateSignatureOnBinary {

	public static byte[] generateSignatureOnBinary(final byte[] data, final PrivateKey privateKey,
			final String algorithm) throws Exception {
		final Signature dsa = Signature.getInstance(algorithm);
		dsa.initSign(privateKey);
		dsa.update(data);
		return dsa.sign();
	}

	public static boolean validateSignatureOnBinary(final byte[] data, final PublicKey publicKey,
			final byte[] signature, final String algorithm) throws Exception {
		final Signature signer = Signature.getInstance(algorithm);
		signer.initVerify(publicKey);
		signer.update(data);
		return signer.verify(signature);

	}

	public static void main(final String args[]) throws Exception {
		final KeyPair keyPair = GenerateKeyPair.generate("SHA1PRNG", 1008, "base64");

		final byte[] data = { 65, 66, 67, 68, 69, 70, 71, 72, 73, 74 };
		final boolean validate = validateSignatureOnBinary(data, keyPair.getPublic(), null, "SHA1withDSA");

		System.out.println("Validate:\n" + validate);
	}

}
