package ro.kuberam.libs.java.crypto.providers;

import java.security.Provider;
import java.security.Provider.Service;

import org.junit.Test;

import java.security.Security;

import static org.junit.Assert.*;

public class ListDSAProviderTest {

	@Test
	public void list() {
		final Provider[] providers = Security.getProviders();
		assertNotNull(providers);
		assertTrue(providers.length > 1);

		boolean foundDsa = false;
		for (final Provider p : providers) {
			final Service s = p.getService("KeyPairGenerator", "DSA");
			if (s != null) {
				foundDsa = true;
			}
		}

		assertTrue("JDK should always implement DSA", foundDsa);
	}
}
