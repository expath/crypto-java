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

import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.Test;

import ro.kuberam.libs.java.crypto.CryptoModuleTests;

public class AsymmetricEncryptionTest extends CryptoModuleTests {

	@Test
	public void encryptStringWithRsaAsymmetricKey() throws Exception {
		String transformation = "RSA/ECB/NoPadding";
		String publicKey = new String(
				Files.readAllBytes(Paths.get(getClass().getResource("../rsa-public-key.key").toURI())), UTF_8);		
		String privateKey = new String(
				Files.readAllBytes(Paths.get(getClass().getResource("../rsa-private-key.key").toURI())), UTF_8);


		String encryptedText = AsymmetricEncryption.encryptString(longString, publicKey, transformation);
		String decryptedText = AsymmetricEncryption.decryptString(encryptedText, privateKey, transformation);

		System.out.println(encryptedText);
		System.out.println(decryptedText);
	}
}
