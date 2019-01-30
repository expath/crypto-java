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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;

import java.io.IOException;

import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import ro.kuberam.libs.java.crypto.CryptoError;
import ro.kuberam.libs.java.crypto.CryptoException;
import ro.kuberam.libs.java.crypto.CryptoModuleTests;
import ro.kuberam.libs.java.crypto.digest.Hash;

public class SymmetricEncryptionTest extends CryptoModuleTests {
	private static String aesAlgorithmCbcMode = "AES/CBC/PKCS5Padding";
	private static String aesAlgorithmEcbMode = "AES";
	private static String key = "1234567890123456";
	private static String wrongKey = "17";
	private static String iv;

	@BeforeClass
	public static void beforeClassFunction() {
		try {
			iv = Hash.hashString("initialization vector", "MD5", "hex");
		} catch (CryptoException e) {
			e.printStackTrace();
		}
	}

	@Test
	public void aesAlgorithmAndDefaultProviderAndCbcMode() throws Exception {
		byte[] encryptionResult = SymmetricEncryption.encrypt(longInputBytes, key, aesAlgorithmCbcMode, iv, "");
		byte[] decryptionResult = SymmetricEncryption.decrypt(encryptionResult, key, aesAlgorithmCbcMode, iv, "");

		assertEquals(longInput, new String(decryptionResult, UTF_8));
	}

	@Test
	public void aesAlgorithmAndCbcMode() throws Exception {
		byte[] encryptionResult = SymmetricEncryption.encrypt(longInputBytes, key, aesAlgorithmCbcMode, iv,
				sunProvider);
		byte[] decryptionResult = SymmetricEncryption.decrypt(encryptionResult, key, aesAlgorithmCbcMode, iv,
				sunProvider);

		assertEquals(longInput, new String(decryptionResult, UTF_8));
	}
	
	@Test
	public void aesAlgorithmAndDefaultProviderAndEcbMode() throws Exception {
		byte[] encryptionResult = SymmetricEncryption.encrypt(longInputBytes, key, aesAlgorithmEcbMode, "", "");
		byte[] decryptionResult = SymmetricEncryption.decrypt(encryptionResult, key, aesAlgorithmEcbMode, "", "");

		assertEquals(longInput, new String(decryptionResult, UTF_8));
	}

	@Ignore
	@Test
	public void aesAlgorithmAndWrongKeyAndDefaultProviderAndCbcMode() throws IOException, CryptoException {
		try {
			byte[] encryptionResult = SymmetricEncryption.encrypt(longInputBytes, key, aesAlgorithmCbcMode, iv, "");
			SymmetricEncryption.decrypt(encryptionResult, wrongKey, aesAlgorithmCbcMode, iv, "");
		} catch (CryptoException e) {
			assertEquals(CryptoError.InvalidKeySpecException, e.getCryptoError());
		}
	}
}
