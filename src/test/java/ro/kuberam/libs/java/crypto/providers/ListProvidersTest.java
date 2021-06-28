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
package ro.kuberam.libs.java.crypto.providers;

import javax.xml.stream.FactoryConfigurationError;
import javax.xml.transform.stream.StreamResult;

import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

import java.security.Provider;
import java.security.Security;
import java.util.Iterator;
import java.util.Set;

public class ListProvidersTest {

	@Ignore
	@Test
	public void listProviders() throws FactoryConfigurationError, Exception {
		StreamResult providers = ListProviders.listProviders();
		String providersString = providers.getWriter().toString();
		assertTrue(providersString.contains("SunJCE"));
	}

	@Test
	public void listProviders2() throws FactoryConfigurationError {
		for (Provider provider : Security.getProviders()) {
			final Set keys = provider.keySet();

			System.out.println(provider.getName());
			System.out.println("   " + provider.getVersion());			
			System.out.println("   " + provider.getInfo());

			for (Iterator it = keys.iterator(); it.hasNext();) {

				String key = (String) it.next();
				key = key.split(" ")[0];

				if (key.startsWith("Alg.Alias")) {
					// Strip the alias
					key = key.substring(10);
				}

				final int ix = key.indexOf('.');
				//System.out.println("\t" + key);

			}
		}
	}

}
