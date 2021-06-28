/*
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
package ro.kuberam.libs.java.crypto.toDo;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.crypto.dsig.spec.*;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.*;

import org.w3c.dom.*;

/**
 * Sign XML file.
 */
public class SignFileExample {
    private static String KEY_STORE_TYPE = "JKS";
    private static String KEY_STORE_NAME = "/home/claudius/mykeystoreEXist.ks";
    private static String KEY_STORE_PASS = "ab987c";
    private static String PRIVATE_KEY_PASS = "kpi135";
    private static String KEY_ALIAS = "eXist";

    private static String PATH = "/PatientRecord/Account";
    private static String ID = "acct";

    private static enum SignatureType {
        SIGN_BY_ID,
        SIGN_BY_PATH,
        SIGN_WHOLE_DOCUMENT
    }

    public static void main(final String[] args) throws Exception {
        /*if (args.length < 2) {
        usage();
        return;
        }*/

        final String inputFile = "doc.xml";
        final String outputFile = "doc-signed.xml";

        final SignatureType sigType;
        if (args.length >= 3) {
            if ("id".equals(args[2])) {
                sigType = SignatureType.SIGN_BY_ID;
            } else if ("path".equals(args[2])) {
                sigType = SignatureType.SIGN_BY_PATH;
            } else {
                sigType = SignatureType.SIGN_WHOLE_DOCUMENT;
            }
        } else {
            sigType = SignatureType.SIGN_WHOLE_DOCUMENT;
        }

        // Instantiate the document to be signed
        final DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        final Document doc;

        try (final InputStream is = Files.newInputStream(Paths.get(inputFile))) {
            doc = dbFactory
                    .newDocumentBuilder()
                    .parse(is);
        }

        // prepare signature factory
        final String providerName = System.getProperty(
                "jsr105Provider",
                "org.jcp.xml.dsig.internal.dom.XMLDSigRI"
        );

        final XMLSignatureFactory sigFactory = XMLSignatureFactory.getInstance(
                "DOM",
                (Provider) Class.forName(providerName).newInstance()
        );

        Node nodeToSign = null;
        Node sigParent = null;
        String referenceURI = null;
        XPathExpression expr = null;
        NodeList nodes;
        List transforms = null;

        final XPathFactory factory = XPathFactory.newInstance();
        final XPath xpath = factory.newXPath();
        switch (sigType) {
            case SIGN_BY_ID:
                expr = xpath.compile(
                        String.format("//*[@id='%s']", ID)
                );
                nodes = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
                if (nodes.getLength() == 0) {
                    System.out.println("Can't find node with id: " + ID);
                    return;
                }

                nodeToSign = nodes.item(0);
                sigParent = nodeToSign.getParentNode();
                referenceURI = "#" + ID;
        /*
                 * This is not needed since the signature is alongside the signed element, not enclosed in it.
		transforms = Collections.singletonList(
			    	sigFactory.newTransform(
				    Transform.ENVELOPED,
				    (TransformParameterSpec) null
				)
			    );
		    */
                break;
            case SIGN_BY_PATH:
                // Find the node to be signed by PATH
                expr = xpath.compile(PATH);
                nodes = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
                if (nodes.getLength() < 1) {
                    System.out.println("Invalid document, can't find node by PATH: " + PATH);
                    return;
                }

                nodeToSign = nodes.item(0);
                sigParent = nodeToSign.getParentNode();
                referenceURI = ""; // Empty string means whole document
                transforms = new ArrayList<Transform>() {{
                    add(sigFactory.newTransform(
                            Transform.XPATH,
                            new XPathFilterParameterSpec(PATH)
                            )
                    );
                    add(sigFactory.newTransform(
                            Transform.ENVELOPED,
                            (TransformParameterSpec) null
                            )
                    );
                }};

                break;
            default:
                sigParent = doc.getDocumentElement();
                referenceURI = ""; // Empty string means whole document
                transforms = Collections.singletonList(
                        sigFactory.newTransform(
                                Transform.ENVELOPED,
                                (TransformParameterSpec) null
                        )
                );
                break;
        }


        // Retrieve signing key
        final KeyStore keyStore;
        try (final InputStream is = Files.newInputStream(Paths.get(KEY_STORE_NAME))) {
            keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
            keyStore.load(is, KEY_STORE_PASS.toCharArray());
        }

        final PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, PRIVATE_KEY_PASS.toCharArray());

        final X509Certificate cert = (X509Certificate) keyStore.getCertificate(KEY_ALIAS);
        PublicKey publicKey = cert.getPublicKey();

        // Create a KeyValue containing the RSA PublicKey
        final KeyInfoFactory keyInfoFactory = sigFactory.getKeyInfoFactory();
        final KeyValue keyValue = keyInfoFactory.newKeyValue(publicKey);

        // Create a KeyInfo and add the KeyValue to it
        final KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(keyValue));


        // Create a Reference to the enveloped document
        final Reference ref = sigFactory.newReference(
                referenceURI,
                sigFactory.newDigestMethod(DigestMethod.SHA1, null),
                transforms,
                null,
                null
        );

        // Create the SignedInfo
        final SignedInfo signedInfo = sigFactory.newSignedInfo(
                sigFactory.newCanonicalizationMethod(
                        CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
                        (C14NMethodParameterSpec) null
                ),
                sigFactory.newSignatureMethod(
                        SignatureMethod.DSA_SHA1,
                        null
                ),
                Collections.singletonList(ref)
        );


        // Create a DOMSignContext and specify the RSA PrivateKey and
        // location of the resulting XMLSignature's parent element
        final DOMSignContext dsc = new DOMSignContext(
                privateKey,
                sigParent
        );

        // Create the XMLSignature (but don't sign it yet)
        final XMLSignature signature = sigFactory.newXMLSignature(signedInfo, keyInfo);

        // Marshal, generate (and sign) the enveloped signature
        signature.sign(dsc);

        // output the resulting document
        try (final OutputStream os = Files.newOutputStream(Paths.get(args[1]))) {
            final Transformer trans = TransformerFactory.newInstance().newTransformer();
            trans.transform(new DOMSource(doc), new StreamResult(os));
        }
    }

    private static void usage() {
        System.out.println("Usage: java SignFile <inputFile> <outputFile> [id|path|whole]");
    }
}

