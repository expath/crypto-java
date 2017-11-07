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
/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package ro.kuberam.libs.java.crypto.toDo;

/**
 * @author claudius
 */
// -----------------------------------------------------------------------------
// ListAvailableCryptographicServices.java
// -----------------------------------------------------------------------------

/*
 * =============================================================================
 * Copyright (c) 1998-2009 Jeffrey M. Hunter. All rights reserved.
 *
 * All source code and material located at the Internet address of
 * http://www.idevelopment.info is the copyright of Jeffrey M. Hunter and
 * is protected under copyright laws of the United States. This source code may
 * not be hosted on any other site without my express, prior, written
 * permission. Application to host any of the material elsewhere can be made by
 * contacting me at jhunter@idevelopment.info.
 *
 * I have made every effort and taken great care in making sure that the source
 * code and other content included on my web site is technically accurate, but I
 * disclaim any and all responsibility for any loss, damage or destruction of
 * data or any other property which may arise from relying on it. I will in no
 * case be liable for any monetary damages arising from such loss, damage or
 * destruction.
 *
 * As with any code, ensure to test this code in a development environment
 * before attempting to run it in production.
 * =============================================================================
 */

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Set;
import java.util.HashSet;
import java.util.Iterator;

/**
 * -----------------------------------------------------------------------------
 * The providers of cryptographic services such as key generation algorithms,
 * register their services with the <code>Security</code> class. A service is
 * represented by a name of the form:
 *
 * <i>service-type.service-implementation</i>
 *
 * An example of a service entry is:
 * <code>SecureRandom.SHA1PRNG</code>
 * -----------------------------------------------------------------------------
 * @version 1.0
 * @author Jeffrey M. Hunter  (jhunter@idevelopment.info)
 * @author http://www.idevelopment.info
 * -----------------------------------------------------------------------------
 */

public class ListAvailableCryptographicServices {

    /**
     * This method returns all available services types.
     * @return <code>String[]</code> object that is a list of all available
     *                               service types.
     */
    private static String[] getServiceTypes() {

        final Set<String> result = new HashSet<>();

        // All providers
        final Provider[] providers = Security.getProviders();
        for (int i = 0; i < providers.length; i++) {

            // Get services provided by each provider
            final Set keys = providers[i].keySet();

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
     * This method returns the available implementations for a given
     * service type.
     * @param serviceType A String object that represents a particular service
     *                    type
     * @return <code>String[]</code> object that is a list of all available
     *                               service type implementations.
     */
    private static String[] getCryptoImpls(final String serviceType) {

        final Set<String> result = new HashSet<>();

        // All providers
        final Provider[] providers = Security.getProviders();
        for (int i = 0; i < providers.length; i++) {

            // Get services provided by each provider
            final Set keys = providers[i].keySet();

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

        final String[] serviceTypes = getServiceTypes();
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
//http://exampledepot.com/egs/java.security/ListServices.html
//http://informit.com/guides/content.aspx?g=java&seqNum=31

         /*String providerName = "SUN version 1.6";
         Provider providers[];
         if(null != args && 0 < args.length)
         {
         providers = new Provider[args.length];
         for(int i = 0; i < args.length; i++)
         providers[i] = Security.getProvider(args[i]);

         } else
         {
         providers = Security.getProviders();
         }
         for(int i = 0; i < providers.length; i++)
         {
         Provider p = providers[i];
         System.out.println("Provider: " + p);
         System.out.println("===============================");
         System.out.println("provider properties:");
         ArrayList keys = new ArrayList(p.keySet());
         Collections.sort(keys);
         String key;
         for(Iterator j = keys.iterator(); j.hasNext();
         System.out.println(key + "=" + p.get(key)))
         key = (String)j.next();

         System.out.println("-------------------------------");
         }*/
         