package ro.kuberam.libs.java.crypto.providers;

import java.security.Provider;
import java.security.Provider.Service;

import org.junit.Test;

import java.security.Security;

public class ListDSAProviderTest {

	@Test
	public void list() throws Exception {
		final Provider[] providers = Security.getProviders();
		for (final Provider p : providers) {
			Service s = p.getService("KeyPairGenerator", "DSA");
			if (s == null) {
				continue;
			}

			System.out.println(p.getName());
		}
	}

}
