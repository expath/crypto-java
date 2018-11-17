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

import ro.kuberam.libs.java.crypto.digest.Hash;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertEquals;

public class EncryptAndDecryptStringWithAesSymmetricKeyAndDefaultProviderCbcMode extends BaseTest {

	@Test
	public void encryptStringWithAesSymmetricKey() throws Exception {
		String input = "Short string for tests.";
		String plainKey = "1234567890123456";
		String transformationName = "AES/CBC/PKCS5Padding";
		String iv = Hash.hashString("initialization vector", "MD5", "hex");
		

		String encryptionResult = SymmetricEncryption.encryptString(input, plainKey, transformationName, iv, "");
		System.out.println(encryptionResult);
		assertEquals(
				"51-143-171-200-187-20-34-252-231-243-254-42-36-13-9-123-191-251-243-42-3-238-193-13-155-168-139-67-135-3-143-54",
				encryptionResult);

		String decryptionResult = SymmetricEncryption.decryptString(encryptionResult, plainKey, transformationName, iv,
				"");

		System.out.println(decryptionResult);
	}
}
