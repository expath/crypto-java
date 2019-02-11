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

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import ro.kuberam.tests.junit.BaseTest;

public class CryptoModuleTests extends BaseTest {

	protected static String longString = "Long string for tests. Long string for tests. Long string for tests. Long string for tests. Long string for tests.";
	protected static String veryLongString;
	protected static byte[] longInputBytes = longString.getBytes(UTF_8);
	protected static String sunProvider = "SunJCE";
	protected static Path rsaPrivateKeyFile = Paths.get("rsa-private-key.key").toAbsolutePath();
	protected static Path rsaPublicKeyFile = Paths.get("rsa-public-key.key").toAbsolutePath();
	
	static {
		try {
			veryLongString = new String(
					Files.readAllBytes(Paths.get(CryptoModuleTests.class.getResource("very-long-string.txt").toURI())), UTF_8);
		} catch (IOException | URISyntaxException e) {
			e.printStackTrace();
		}
	}
}
