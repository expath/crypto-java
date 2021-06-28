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
package ro.kuberam.libs.java.crypto.digitalSignature;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilterParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;

public class GenerateSignature {

	public static byte[] generateSignature(byte[] data, PrivateKey key, String algorithm, String provider)
			throws Exception {
		Signature signer = Signature.getInstance(algorithm);
		signer.initSign(key);
		signer.update(data);

		return signer.sign();
	}

	public static String GenerateDigitalSignature(org.w3c.dom.Document inputDoc, String canonicalizationAlgorithmURI,
			String digestAlgorithmURI, String signatureAlgorithmURI, String keyPairAlgorithm,
			String signatureNamespacePrefix, String signatureType, String xpathExprString, String[] certificateDetails,
			InputStream keyStoreInputStream) throws Exception {
		// Create a DOM XMLSignatureFactory
		String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
		XMLSignatureFactory sigFactory = XMLSignatureFactory.getInstance("DOM");

		// Create a Reference to the signed element
		Node sigParent;
		List<Transform> transforms;

		if (xpathExprString == null) {
			sigParent = inputDoc.getDocumentElement();
			transforms = Collections
					.singletonList(sigFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
		} else {
			XPathFactory factory = XPathFactory.newInstance();
			XPath xpath = factory.newXPath();
			// Find the node to be signed by PATH
			XPathExpression expr = xpath.compile(xpathExprString);
			NodeList nodes = (NodeList) expr.evaluate(inputDoc, XPathConstants.NODESET);
			if (nodes.getLength() < 1) {
				throw new Exception("Can't find node by this XPath expression: " + xpathExprString);
			}

			// Node nodeToSign = nodes.item(0);
			// sigParent = nodeToSign.getParentNode();
			sigParent = nodes.item(0);
			/*
			 * if ( signatureType.equals( "enveloped" ) ) { sigParent = ( nodes.item(0)
			 * ).getParentNode(); }
			 */
			transforms = Arrays.asList(
					sigFactory.newTransform(Transform.XPATH, new XPathFilterParameterSpec(xpathExprString)),
					sigFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
		}

		Reference ref = sigFactory.newReference("", sigFactory.newDigestMethod(digestAlgorithmURI, null), transforms,
				null, null);

		// http://www.massapi.com/source/xml-security-1_4_4/src/org/jcp/xml/dsig/internal/dom/DOMXPathFilter2Transform.java.html

		// Create the SignedInfo
		SignedInfo si = sigFactory.newSignedInfo(
				sigFactory.newCanonicalizationMethod(canonicalizationAlgorithmURI, (C14NMethodParameterSpec) null),
				sigFactory.newSignatureMethod(signatureAlgorithmURI, null), Collections.singletonList(ref));

		// generate key pair
		KeyInfo ki;
		PrivateKey privateKey;
		if (certificateDetails[0].length() != 0) {
			KeyStore keyStore;
			try {
				keyStore = KeyStore.getInstance(certificateDetails[0]);
			} catch (Exception ex) {
				throw new Exception("The keystore type '" + certificateDetails[0] + "' is not supported!.");
			}
			keyStore.load(keyStoreInputStream, certificateDetails[1].toCharArray());
			String alias = certificateDetails[2];
			if (!keyStore.containsAlias(alias)) {
				throw new Exception("Cannot find key for alias '" + alias + "' in given keystore!.");
			}
			privateKey = (PrivateKey) keyStore.getKey(alias, certificateDetails[3].toCharArray());

			X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
			PublicKey publicKey = cert.getPublicKey();
			KeyInfoFactory kif = sigFactory.getKeyInfoFactory();

			List<XMLStructure> kiContent = new ArrayList<>();
			KeyValue keyValue = kif.newKeyValue(publicKey);
			kiContent.add(keyValue);

			List<Object> x509Content = new ArrayList<>();
			X509IssuerSerial issuer = kif.newX509IssuerSerial(cert.getIssuerX500Principal().getName(),
					cert.getSerialNumber());
			x509Content.add(cert.getSubjectX500Principal().getName());
			x509Content.add(issuer);
			x509Content.add(cert);

			X509Data x509Data = kif.newX509Data(x509Content);
			kiContent.add(x509Data);
			ki = kif.newKeyInfo(kiContent);
		} else {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyPairAlgorithm);
			kpg.initialize(512);
			KeyPair kp = kpg.generateKeyPair();
			KeyInfoFactory kif = sigFactory.getKeyInfoFactory();
			KeyValue kv = kif.newKeyValue(kp.getPublic());
			ki = kif.newKeyInfo(Collections.singletonList(kv));
			privateKey = kp.getPrivate();
		}

		/*
		 * <element name="X509Data" type="ds:X509DataType"/> <complexType
		 * name="X509DataType"> <sequence maxOccurs="unbounded"> <choice> SOLVED
		 * <element name="X509IssuerSerial" type="ds:X509IssuerSerialType"/> <element
		 * name="X509SKI" type="base64Binary"/> SOLVED <element name="X509SubjectName"
		 * type="string"/> SOLVED <element name="X509Certificate" type="base64Binary"/>
		 * <element name="X509CRL" type="base64Binary"/> <any namespace="##other"
		 * processContents="lax"/> </choice> </sequence> </complexType> >
		 */

		// Create a DOMSignContext and specify the location of the resulting
		// XMLSignature's parent element
		DOMSignContext dsc;
		XMLSignature signature;
		Document signatureDoc = null;
		if (signatureType.equals("enveloped")) {
			dsc = new DOMSignContext(privateKey, sigParent);
			signature = sigFactory.newXMLSignature(si, ki);
		} else if (signatureType.equals("detached")) {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			sigParent = dbf.newDocumentBuilder().newDocument();
			dsc = new DOMSignContext(privateKey, sigParent);
			signature = sigFactory.newXMLSignature(si, ki);
		} else if (signatureType.equals("enveloping")) {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			signatureDoc = dbf.newDocumentBuilder().newDocument();
			XMLStructure content = new DOMStructure(sigParent);
			XMLObject xmlobj = sigFactory.newXMLObject(Collections.singletonList(content), "object", null, null);
			dsc = new DOMSignContext(privateKey, signatureDoc);
			signature = sigFactory.newXMLSignature(si, ki, Collections.singletonList(xmlobj), null, null);
		} else {
			// TODO(AR) error, as below will cause NPE...
			dsc = null;
			signature = null;
		}

		dsc.setDefaultNamespacePrefix(signatureNamespacePrefix);

		// Marshal, generate and sign
		signature.sign(dsc);

		DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
		DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
		LSSerializer serializer = impl.createLSSerializer();
		if (signatureType.equals("enveloping")) {
			return serializer.writeToString(signatureDoc);
		} else {
			return serializer.writeToString(sigParent);
		}
	}
}
