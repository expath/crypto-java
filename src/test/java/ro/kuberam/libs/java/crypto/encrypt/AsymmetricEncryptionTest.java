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

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

import org.junit.Test;

import ro.kuberam.libs.java.crypto.CryptoModuleTests;
import ro.kuberam.libs.java.crypto.keyManagement.GenerateKeyPair;
import ro.kuberam.libs.java.crypto.keyManagement.Load;

public class AsymmetricEncryptionTest extends CryptoModuleTests {

	@Test
	public void encryptAndDecryptStringWithRsaAsymmetricKey() throws Exception {
		String transformation = "RSA/ECB/PKCS1Padding";
		String algorithm = "RSA";

		String base64PublicKey = new String(
				Files.readAllBytes(Paths.get(getClass().getResource("../rsa-public-key.key").toURI())), UTF_8);
		PublicKey publicKey = Load.publicKey(base64PublicKey, algorithm, null);

		String base64PrivateKey = new String(
				Files.readAllBytes(Paths.get(getClass().getResource("../rsa-private-key.key").toURI())), UTF_8);
		PrivateKey privateKey = Load.privateKey(base64PrivateKey, algorithm, null);

		String encryptedText = AsymmetricEncryption.encryptString(longString, publicKey, transformation);
		String decryptedText = AsymmetricEncryption.decryptString(encryptedText, privateKey, transformation);

		assertEquals(longString, decryptedText);
	}

	@Test
	public void encryptAndDecryptStringWithAdHocGeneratedKey() throws Exception {
		String transformation = "RSA/ECB/PKCS1Padding";
		String algorithm = "RSA";
		Map<String, String> keys = GenerateKeyPair.run("RSA");

		PublicKey publicKey = Load.publicKey(keys.get("public-key"), algorithm, null);
		PrivateKey privateKey = Load.privateKey(keys.get("private-key"), algorithm, null);

		String encryptedText = AsymmetricEncryption.encryptString(longString, publicKey, transformation);
		String decryptedText = AsymmetricEncryption.decryptString(encryptedText, privateKey, transformation);

		assertEquals(longString, decryptedText);
	}
}
