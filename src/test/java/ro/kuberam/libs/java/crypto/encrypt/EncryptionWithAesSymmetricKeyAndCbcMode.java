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

import ro.kuberam.libs.java.crypto.digest.Hash;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertEquals;

public class EncryptionWithAesSymmetricKeyAndCbcMode extends BaseTest {

	@Test
	public void encryptStringWithAesSymmetricKey() throws Exception {
		String input = "Long string for tests. Long string for tests. Long string for tests. Long string for tests. Long string for tests.";
		String plainKey = "1234567890123456";
		String transformationName = "AES/CBC/PKCS5Padding";
		String iv = Hash.hashString("initialization vector", "MD5", "hex");

		byte[] encryptionResult = SymmetricEncryption.encrypt(input.getBytes(UTF_8), plainKey, transformationName, iv,
				"SunJCE");
		byte[] decryptionResult = SymmetricEncryption.decrypt(encryptionResult, plainKey, transformationName, iv, "SunJCE");

		assertEquals(input, new String(decryptionResult, UTF_8));
	}
}
