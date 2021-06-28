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
package ro.kuberam.libs.java.crypto.keyManagement;

import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class TranslateKeyTest {

	@Test
	public void rsaKeyPair() throws Exception {
		String algorithm = "DSA";
		String keyGenerationProvider = "SUN";
		final GenerateKeyPair.GeneratedKeys keys = GenerateKeyPair.run(algorithm, keyGenerationProvider);
		assertNotNull(keys);

		assertNotNull(keys.getPrivateKey());
		assertTrue(keys.getPrivateKey().matches("-----BEGIN DSA PRIVATE KEY-----\n[^-]+-----END DSA PRIVATE KEY-----\n"));

		assertNotNull(keys.getPublicKey());
		assertTrue(keys.getPublicKey().matches("-----BEGIN DSA PUBLIC KEY-----\n[^-]+-----END DSA PUBLIC KEY-----\n"));
	}
}
