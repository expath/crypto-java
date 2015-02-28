package ro.kuberam.libs.java.crypto.junit.providers;

import javax.xml.stream.FactoryConfigurationError;
import javax.xml.transform.stream.StreamResult;

import org.junit.Assert;
import org.junit.Test;

import ro.kuberam.libs.java.crypto.providers.ListProviders;
import ro.kuberam.tests.junit.BaseTest;

public class ListProvidersTest extends BaseTest {

	@Test
	public void listProviders() throws FactoryConfigurationError, Exception {
		StreamResult providers = ListProviders.listProviders();
		String providersString = providers.getWriter().toString();
		System.out.println(prettyPrintXmlString(providersString));
		Assert.assertTrue(providersString.contains("SunJCE"));
	}

}
