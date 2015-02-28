package ro.kuberam.libs.java.crypto.providers;

/**
 *
 * @author claudius
 */

import java.io.StringWriter;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Date;
import java.util.Set;
import java.util.HashSet;
import java.util.Iterator;

import javax.xml.stream.FactoryConfigurationError;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.stream.StreamResult;

import org.apache.log4j.Logger;

import ro.kuberam.libs.java.crypto.ExpathCryptoModule;


public class ListServices {
	private static final Logger log = Logger.getLogger(ListServices.class);
	private static String moduleNsUri = "";
	static {
		moduleNsUri = ExpathCryptoModule.NAMESPACE_URI;
	}
	private static String modulePrefix = "";
	static {
		modulePrefix = ExpathCryptoModule.PREFIX;
	}

	public static StreamResult listServices(String providerName)
			throws XMLStreamException, FactoryConfigurationError {
		long startTime = new Date().getTime();
		
		Provider[] providers = Security.getProviders();
		

		StringWriter writer = new StringWriter();
		XMLStreamWriter xmlWriter = XMLOutputFactory.newInstance()
				.createXMLStreamWriter(writer);
		xmlWriter.setPrefix(modulePrefix, moduleNsUri);
		xmlWriter.writeStartDocument();
		xmlWriter.writeStartElement(modulePrefix + ":providers-list");
		xmlWriter.writeNamespace(modulePrefix, moduleNsUri);
		for (Provider provider : Security.getProviders()) {
			xmlWriter.writeStartElement(modulePrefix + ":provider");
			xmlWriter.writeCharacters(provider.getName());
			xmlWriter.writeEndElement();
		}
		xmlWriter.writeEndElement();
		xmlWriter.writeEndDocument();
		xmlWriter.close();

		StreamResult resultAsStreamResult = new StreamResult(writer);
		log.info("The list with cryptographic services for provider "
				+ providerName + " was generated in "
				+ (new Date().getTime() - startTime) + " ms.");

		return resultAsStreamResult;
	}

}
