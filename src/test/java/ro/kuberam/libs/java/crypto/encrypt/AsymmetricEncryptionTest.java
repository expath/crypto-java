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

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import java.io.InputStream;

import static java.nio.charset.StandardCharsets.UTF_8;

public class AsymmetricEncryptionTest extends BaseTest {

	@Test
	public void encryptStringWithAesSymmetricKey() throws Exception {
		String input = "Short string for tests.";
		try (InputStream is = getClass().getResourceAsStream("../rsa-public-key.pub")) {
			String publicKey = IOUtils.toString(is, UTF_8);
			System.out.println("publicKey = " + publicKey);

			String result = AsymmetricEncryption.encryptString(input, publicKey,
					"RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

			System.out.println(result);
		}
	}

}
