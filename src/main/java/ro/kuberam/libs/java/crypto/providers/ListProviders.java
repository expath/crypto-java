package ro.kuberam.libs.java.crypto.providers;

import java.io.IOException;
import java.io.StringWriter;
import java.security.Provider;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;

import javax.xml.stream.FactoryConfigurationError;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.stream.StreamResult;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ro.kuberam.libs.java.crypto.ExpathCryptoModule;

public class ListProviders {
    private static final Logger LOG = LogManager.getLogger(ListProviders.class);
    private static final String moduleNsUri = ExpathCryptoModule.NAMESPACE_URI;
    private static final String modulePrefix = ExpathCryptoModule.PREFIX;

    public static StreamResult listProviders() throws XMLStreamException,
            FactoryConfigurationError, IOException {
        final long startTime = new Date().getTime();

        try (final StringWriter writer = new StringWriter()) {
            final XMLStreamWriter xmlWriter = XMLOutputFactory.newInstance()
                    .createXMLStreamWriter(writer);
            xmlWriter.setPrefix(modulePrefix, moduleNsUri);
            xmlWriter.writeStartDocument();
            xmlWriter.writeStartElement(modulePrefix + ":providers-list");
            xmlWriter.writeNamespace(modulePrefix, moduleNsUri);

            for (final Provider provider : Security.getProviders()) {
                xmlWriter.writeStartElement(modulePrefix + ":provider");
                xmlWriter.writeAttribute("name", provider.getName());
                xmlWriter.writeAttribute("version", Double.toString(provider.getVersion()));
                final Set keys = provider.keySet();

                System.out.println(provider.elements().nextElement().toString());

                for (Iterator it = keys.iterator(); it.hasNext(); ) {

                    String key = (String) it.next();
                    key = key.split(" ")[0];

                    if (key.startsWith("Alg.Alias")) {
                        // Strip the alias
                        key = key.substring(10);
                    }

                    final int ix = key.indexOf('.');
                    //System.out.println(key);


                }
                xmlWriter.writeEndElement();
            }
            xmlWriter.writeEndElement();
            xmlWriter.writeEndDocument();
            xmlWriter.close();

            final StreamResult resultAsStreamResult = new StreamResult(writer);
            if (LOG.isDebugEnabled()) {
                LOG.debug("The list with cryptographic providers was generated in "
                        + (new Date().getTime() - startTime) + " ms.");
            }

            return resultAsStreamResult;
        }
    }

}


//import java.security.Provider;
//import java.security.Security;
//import java.util.Enumeration;
//
//public class MainClass {
//  public static void main(String[] args) throws Exception {
//    try {
//      Provider p[] = Security.getProviders();
//      for (int i = 0; i < p.length; i++) {
//          System.out.println(p[i]);
//          for (Enumeration e = p[i].keys(); e.hasMoreElements();)
//              System.out.println("\t" + e.nextElement());
//      }
//    } catch (Exception e) {
//      System.out.println(e);
//    }
//  }
//}