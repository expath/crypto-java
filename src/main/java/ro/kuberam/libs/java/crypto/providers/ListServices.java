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

/**
 * @author claudius
 */

import java.io.IOException;
import java.io.StringWriter;
import java.security.Provider;
import java.security.Security;
import java.util.Date;

import javax.xml.stream.FactoryConfigurationError;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.stream.StreamResult;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ro.kuberam.libs.java.crypto.ExpathCryptoModule;

public class ListServices {
    private static final Logger LOG = LogManager.getLogger(ListServices.class);
    private static final String moduleNsUri = ExpathCryptoModule.NAMESPACE_URI;
    private static final String modulePrefix = ExpathCryptoModule.PREFIX;

    public static StreamResult listServices(final String providerName) throws XMLStreamException, FactoryConfigurationError, IOException {
        final long startTime = new Date().getTime();

        try (final StringWriter writer = new StringWriter()) {
            final XMLStreamWriter xmlWriter = XMLOutputFactory.newInstance().createXMLStreamWriter(writer);
            xmlWriter.setPrefix(modulePrefix, moduleNsUri);
            xmlWriter.writeStartDocument();
            xmlWriter.writeStartElement(modulePrefix + ":providers-list");
            xmlWriter.writeNamespace(modulePrefix, moduleNsUri);

            for (final Provider provider : Security.getProviders()) {
                xmlWriter.writeStartElement(modulePrefix + ":provider");
                xmlWriter.writeCharacters(provider.getName());
                xmlWriter.writeEndElement();
            }
            xmlWriter.writeEndElement();
            xmlWriter.writeEndDocument();
            xmlWriter.close();

            final StreamResult resultAsStreamResult = new StreamResult(writer);
            if (LOG.isDebugEnabled()) {
                LOG.debug("The list with cryptographic services for provider " + providerName + " was generated in "
                        + (new Date().getTime() - startTime) + " ms.");
            }

            return resultAsStreamResult;
        }
    }

}
