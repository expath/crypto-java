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

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.*;
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
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.*;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;

import ro.kuberam.libs.java.crypto.CryptoError;
import ro.kuberam.libs.java.crypto.CryptoException;

/**
 * Implements the module definition.
 *
 * @author <a href="mailto:claudius.teodorescu@gmail.com">Claudius
 *         Teodorescu</a>
 */

public class GenerateXmlSignature {

	public static String generate(Document inputDoc, String canonicalizationAlgorithm, String digestAlgorithm,
			String signatureAlgorithm, String signatureNamespacePrefix, String signatureType, String xpathExprString,
			String[] certificateDetails, InputStream keyStoreInputStream)
			throws CryptoException, IOException, XMLSignatureException {
		String mechanismType = "DOM";

		return generate(inputDoc, mechanismType, canonicalizationAlgorithm, digestAlgorithm, signatureAlgorithm,
				signatureNamespacePrefix, signatureType, xpathExprString, certificateDetails, keyStoreInputStream);

	}

	public static String generate(Document inputDoc, String mechanismType, String canonicalizationAlgorithm,
			String digestAlgorithm, String signatureAlgorithm, String signatureNamespacePrefix, String signatureType,
			String xpathExprString, String[] certificateDetails, InputStream keyStoreInputStream)
			throws CryptoException, IOException, XMLSignatureException {

		String canonicalizationAlgorithmURI = getCanonicalizationAlgorithmUri(canonicalizationAlgorithm);
		String digestAlgorithmURI = getDigestAlgorithmURI(digestAlgorithm);
		String signatureAlgorithmURI = getSignatureAlgorithmURI(signatureAlgorithm);
		String keyPairAlgorithm = signatureAlgorithm.substring(0, 3);

		// Create a DOM XMLSignatureFactory
		XMLSignatureFactory sigFactory = XMLSignatureFactory.getInstance(mechanismType);

		// Create a Reference to the signed element
		Node sigParent = null;
		List<Transform> transforms;

		try {
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
					// TODO this error message has to replaced
					throw new CryptoException(CryptoError.UNKNOWN_ALGORITHM);
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

			Reference ref = sigFactory.newReference("", sigFactory.newDigestMethod(digestAlgorithmURI, null),
					transforms, null, null);

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
				} catch (KeyStoreException e) {
					throw new CryptoException(e);
				}
				keyStore.load(keyStoreInputStream, certificateDetails[1].toCharArray());
				String alias = certificateDetails[2];
				if (!keyStore.containsAlias(alias)) {
					throw new CryptoException(CryptoError.ALIAS_KEY);
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
			DOMSignContext dsc = null;
			XMLSignature signature = null;
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
			}
			dsc.setDefaultNamespacePrefix(signatureNamespacePrefix);

			// Marshal, generate and sign
			signature.sign(dsc);

			DOMImplementationRegistry registry;
			try {
				registry = DOMImplementationRegistry.newInstance();
			} catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
				throw new IOException(e);
			}
			DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
			LSSerializer serializer = impl.createLSSerializer();
			if (signatureType.equals("enveloping")) {
				return serializer.writeToString(signatureDoc);
			} else {
				return serializer.writeToString(sigParent);
			}
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new CryptoException(CryptoError.UNKNOWN_ALGORITHM, e);
		} catch (CertificateException e) {
			// TODO error code needs improving
			throw new CryptoException(CryptoError.INVALID_CRYPTO_KEY, e);
		} catch (KeyStoreException e) {
			throw new CryptoException(CryptoError.UNREADABLE_KEYSTORE, e);
		} catch (UnrecoverableKeyException | KeyException e) {
			throw new CryptoException(CryptoError.INVALID_CRYPTO_KEY, e);
		} catch (ParserConfigurationException | XPathExpressionException | MarshalException e) {
			throw new IOException(e);
		}
	}

	// public static void main(String[] args) throws
	// ParserConfigurationException,
	// SAXException, IOException, Exception {
	// String docString =
	// "<data><a xml:id=\"type\"><b>23</b><c><d/></c></a></data>";
	// DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	// dbf.setNamespaceAware(true);
	// Document inputDoc = dbf.newDocumentBuilder().parse(
	// new InputSource(new StringReader(docString)));
	//
	// String[] certificateDetails = new String[5];
	// certificateDetails[0] = "JKS";
	// certificateDetails[1] = "ab987c";
	// certificateDetails[2] = "eXist";
	// certificateDetails[3] = "kpi135";
	//
	// String domString = generateXmlSignature(inputDoc,
	// CanonicalizationMethod.EXCLUSIVE, DigestMethod.SHA1,
	// SignatureMethod.DSA_SHA1, "DSA", "ds", "enveloped", "//b",
	// certificateDetails, getClass().getResourceAsStream(
	// "../tests/resources/mykeystoreEXist.ks"));
	// System.out.print(domString + "\n");
	// }

	private static String getCanonicalizationAlgorithmUri(String canonicalizationAlgorithm) throws CryptoException {
		switch (canonicalizationAlgorithm) {
		case "exclusive":
			return CanonicalizationMethod.EXCLUSIVE;

		case "exclusive-with-comments":
			return CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS;

		case "inclusive":
			return CanonicalizationMethod.INCLUSIVE;

		default:
			throw new CryptoException(CryptoError.UNKNOWN_ALGORITHM);
		}
	}

	private static String getDigestAlgorithmURI(String digestAlgorithm) throws CryptoException {
		switch (digestAlgorithm) {
		case "SHA256":
			return DigestMethod.SHA256;

		case "SHA512":
			return DigestMethod.SHA512;

		case "SHA1":
		case "":
			return DigestMethod.SHA1;

		default:
			throw new CryptoException(CryptoError.UNKNOWN_ALGORITHM);
		}
	}

	private static String getSignatureAlgorithmURI(String signatureAlgorithm) throws CryptoException {
		switch (signatureAlgorithm) {
		case "DSA_SHA1":
			return SignatureMethod.DSA_SHA1;

		case "RSA_SHA1":
		case "":
			return SignatureMethod.RSA_SHA1;

		default:
			throw new CryptoException(CryptoError.UNKNOWN_ALGORITHM);
		}
	}
}