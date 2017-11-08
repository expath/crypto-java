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

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import ro.kuberam.tests.junit.BaseTest;

public class ListServicesTest extends BaseTest {

    // @Test
    // public void listServices() throws XMLStreamException,
    // FactoryConfigurationError {
    // StreamResult providers = ListProviders.listProviders();
    // String providersString = providers.getWriter().toString();
    // System.out.println(providersString);
    // Assert.assertTrue(providersString.contains("base64"));
    // }

    private static String[] getServiceTypes() {

        final Set<String> result = new HashSet<>();

        // All providers
        final Provider[] providers = Security.getProviders();
        for (int i = 0; i < providers.length; i++) {

            // Get services provided by each provider
            final Set<Object> keys = providers[i].keySet();

            for (final Iterator it = keys.iterator(); it.hasNext(); ) {

                String key = (String) it.next();
                key = key.split(" ")[0];

                if (key.startsWith("Alg.Alias")) {
                    // Strip the alias
                    key = key.substring(10);
                }

                final int ix = key.indexOf('.');
                result.add(key.substring(0, ix));
            }

        }

        return result.toArray(new String[result.size()]);

    }

    /**
     * * This method returns the available implementations for a given service *
     * type. * * @param serviceType * A String object that represents a
     * particular service type * @return String[] object that is a list of all
     * available * service type implementations.
     */
    private static String[] getCryptoImpls(final String serviceType) {

        final Set<String> result = new HashSet<>();

        // All providers
        final Provider[] providers = Security.getProviders();
        for (int i = 0; i < providers.length; i++) {

            // Get services provided by each provider
            final Set<Object> keys = providers[i].keySet();

            for (final Iterator it = keys.iterator(); it.hasNext(); ) {

                String key = (String) it.next();

                key = key.split(" ")[0];

                if (key.startsWith(serviceType + ".")) {
                    result.add(key.substring(serviceType.length() + 1));
                } else if (key.startsWith("Alg.Alias." + serviceType + ".")) {
                    // This is an alias
                    result.add(key.substring(serviceType.length() + 11));
                }

            }

        }

        return result.toArray(new String[result.size()]);

    }

    /**
     * Print all Service Types (sorted) to STDOUT.
     */
    private static void listServiceTypes() {

        System.out.println();
        System.out.println("Service Types");
        System.out.println("-------------");

        final String[] serviceTypes = getServiceTypes();
        Arrays.sort(serviceTypes);

        for (int i = 0; i < serviceTypes.length; i++) {
            System.out.println("  - " + serviceTypes[i]);
        }
        System.out.println();

    }

    /**
     * Print all Service Type Implementations (sorted) to STDOUT.
     */
    private static void listCryptoImpls() {

        System.out.println();
        System.out.println("Service Type Implementations");
        System.out.println("----------------------------");

        String[] serviceTypes = getServiceTypes();
        Arrays.sort(serviceTypes);

        for (int i = 0; i < serviceTypes.length; i++) {

            System.out.println();
            System.out.println("  - " + serviceTypes[i]);

            final String[] serviceTypeImpls = getCryptoImpls(serviceTypes[i]);
            Arrays.sort(serviceTypeImpls);

            for (int j = 0; j < serviceTypeImpls.length; j++) {
                System.out.println("      " + serviceTypeImpls[j]);
            }

        }
        System.out.println();

    }

    public static void main(final String[] args) {
        listServiceTypes();
        listCryptoImpls();
    }

}
