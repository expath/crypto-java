package ro.kuberam.libs.java.crypto.providers;

import javax.xml.stream.FactoryConfigurationError;
import javax.xml.transform.stream.StreamResult;

import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static org.junit.Assert.assertTrue;

public class ListProvidersTest extends BaseTest {

    @Test
    public void listProviders() throws FactoryConfigurationError, Exception {
        final StreamResult providers = ListProviders.listProviders();
        final String providersString = providers.getWriter().toString();
        System.out.println(prettyPrintXmlString(providersString));
        assertTrue(providersString.contains("SunJCE"));
    }

}
