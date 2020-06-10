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
package ro.kuberam.libs.java.crypto.secureStorage;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

class ReloadableX509TrustManager implements X509TrustManager {
    private final String trustStorePath;
    private X509TrustManager trustManager;
    //private List tempCertList = new List();

    public ReloadableX509TrustManager(final String tspath) throws Exception {
        this.trustStorePath = tspath;
        reloadTrustManager();
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        final X509Certificate[] issuers = trustManager.getAcceptedIssuers();
        return issuers;
    }

    private void reloadTrustManager() throws Exception {

        // load keystore from specified cert store (or default)
        final KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
        try (final InputStream in = Files.newInputStream(Paths.get(trustStorePath))) {
            ts.load(in, null);
        }

        // add all temporary certs to KeyStore (ts)
        //TODO: this below has to be commented out to work
//		for (Certificate cert : tempCertList) {
//			ts.setCertificateEntry(UUID.randomUUID().toString(), cert);
//		}

        // initialize a new TMF with the ts we just loaded
        final TrustManagerFactory tmf = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);

        // acquire X509 trust manager from factory
        final TrustManager tms[] = tmf.getTrustManagers();
        for (int i = 0; i < tms.length; i++) {
            if (tms[i] instanceof X509TrustManager) {
                trustManager = (X509TrustManager) tms[i];
                return;
            }
        }

        throw new NoSuchAlgorithmException(
                "No X509TrustManager in TrustManagerFactory");
    }

    private void addServerCertAndReload(final Certificate cert, final boolean permanent) {
        try {
            if (permanent) {
                // import the cert into file trust store
                // Google "java keytool source" or just ...
                Runtime.getRuntime().exec("keytool -importcert ...");
            } else {
                //TODO: this below has to be commented out to work
//				tempCertList.add(cert);
            }
            reloadTrustManager();
        } catch (Exception ex) { /* ... */
            //what?
        }
    }

    @Override
    public void checkClientTrusted(final X509Certificate[] chain, final String authType)
            throws CertificateException {
        trustManager.checkClientTrusted(chain, authType);

    }

    @Override
    public void checkServerTrusted(final X509Certificate[] chain, final String authType)
            throws CertificateException {
        try {
            trustManager.checkServerTrusted(chain, authType);
        } catch (CertificateException cx) {
            addServerCertAndReload(chain[0], true);
            trustManager.checkServerTrusted(chain, authType);
        }

    }
}