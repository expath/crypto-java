package ro.kuberam.libs.java.crypto.digitalSignature;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
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
import javax.xml.parsers.ParserConfigurationException;
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
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class GenerateSignature {

    public static byte[] generateSignature(final byte[] data, final PrivateKey key, final String algorithm, String provider)
            throws Exception {
        final Signature signer = Signature.getInstance(algorithm);
        signer.initSign(key);
        signer.update(data);
        return signer.sign();
    }

    public static String GenerateDigitalSignature(final org.w3c.dom.Document inputDoc,
                                                  final String canonicalizationAlgorithmURI, final String digestAlgorithmURI, final String signatureAlgorithmURI,
                                                  final String keyPairAlgorithm, final String signatureNamespacePrefix, final String signatureType,
                                                  final String xpathExprString, final String[] certificateDetails, final InputStream keyStoreInputStream)
            throws Exception {
        // Create a DOM XMLSignatureFactory
        final String providerName = System.getProperty("jsr105Provider",
                "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
        final XMLSignatureFactory sigFactory = XMLSignatureFactory.getInstance("DOM");

        // Create a Reference to the signed element
        Node sigParent;
        final List<Transform> transforms;

        if (xpathExprString == null) {
            sigParent = inputDoc.getDocumentElement();
            transforms = Collections.singletonList(sigFactory.newTransform(Transform.ENVELOPED,
                    (TransformParameterSpec) null));
        } else {
            final XPathFactory factory = XPathFactory.newInstance();
            final XPath xpath = factory.newXPath();
            // Find the node to be signed by PATH
            final XPathExpression expr = xpath.compile(xpathExprString);
            final NodeList nodes = (NodeList) expr.evaluate(inputDoc, XPathConstants.NODESET);
            if (nodes.getLength() < 1) {
                throw new Exception("Can't find node by this XPath expression: " + xpathExprString);
            }

            // Node nodeToSign = nodes.item(0);
            // sigParent = nodeToSign.getParentNode();
            sigParent = nodes.item(0);
            /*
			 * if ( signatureType.equals( "enveloped" ) ) { sigParent = (
			 * nodes.item(0) ).getParentNode(); }
			 */
            transforms = Arrays.asList(
                    sigFactory.newTransform(Transform.XPATH, new XPathFilterParameterSpec(
                            xpathExprString)),
                    sigFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
        }

        final Reference ref = sigFactory.newReference("", sigFactory.newDigestMethod(digestAlgorithmURI, null),
                transforms, null, null);

        // http://www.massapi.com/source/xml-security-1_4_4/src/org/jcp/xml/dsig/internal/dom/DOMXPathFilter2Transform.java.html

        // Create the SignedInfo
        final SignedInfo si = sigFactory.newSignedInfo(sigFactory.newCanonicalizationMethod(
                canonicalizationAlgorithmURI, (C14NMethodParameterSpec) null), sigFactory
                .newSignatureMethod(signatureAlgorithmURI, null), Collections.singletonList(ref));

        // generate key pair
        final KeyInfo ki;
        final PrivateKey privateKey;
        if (certificateDetails[0].length() != 0) {
            final KeyStore keyStore;
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

            final X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            final PublicKey publicKey = cert.getPublicKey();
            final KeyInfoFactory kif = sigFactory.getKeyInfoFactory();

            final List<XMLStructure> kiContent = new ArrayList<>();
            final KeyValue keyValue = kif.newKeyValue(publicKey);
            kiContent.add(keyValue);

            final List<Object> x509Content = new ArrayList<>();
            final X509IssuerSerial issuer = kif.newX509IssuerSerial(cert.getIssuerX500Principal().getName(),
                    cert.getSerialNumber());
            x509Content.add(cert.getSubjectX500Principal().getName());
            x509Content.add(issuer);
            x509Content.add(cert);

            final X509Data x509Data = kif.newX509Data(x509Content);
            kiContent.add(x509Data);
            ki = kif.newKeyInfo(kiContent);
        } else {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyPairAlgorithm);
            kpg.initialize(512);
            final KeyPair kp = kpg.generateKeyPair();
            final KeyInfoFactory kif = sigFactory.getKeyInfoFactory();
            final KeyValue kv = kif.newKeyValue(kp.getPublic());
            ki = kif.newKeyInfo(Collections.singletonList(kv));
            privateKey = kp.getPrivate();
        }

		/*
		 * <element name="X509Data" type="ds:X509DataType"/> <complexType
		 * name="X509DataType"> <sequence maxOccurs="unbounded"> <choice> SOLVED
		 * <element name="X509IssuerSerial" type="ds:X509IssuerSerialType"/>
		 * <element name="X509SKI" type="base64Binary"/> SOLVED <element
		 * name="X509SubjectName" type="string"/> SOLVED <element
		 * name="X509Certificate" type="base64Binary"/> <element name="X509CRL"
		 * type="base64Binary"/> <any namespace="##other"
		 * processContents="lax"/> </choice> </sequence> </complexType> >
		 */

        // Create a DOMSignContext and specify the location of the resulting
        // XMLSignature's parent element
        final DOMSignContext dsc;
        final XMLSignature signature;
        Document signatureDoc = null;
        if (signatureType.equals("enveloped")) {
            dsc = new DOMSignContext(privateKey, sigParent);
            signature = sigFactory.newXMLSignature(si, ki);
        } else if (signatureType.equals("detached")) {
            final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            sigParent = dbf.newDocumentBuilder().newDocument();
            dsc = new DOMSignContext(privateKey, sigParent);
            signature = sigFactory.newXMLSignature(si, ki);
        } else if (signatureType.equals("enveloping")) {
            final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            signatureDoc = dbf.newDocumentBuilder().newDocument();
            final XMLStructure content = new DOMStructure(sigParent);
            final XMLObject xmlobj = sigFactory.newXMLObject(Collections.singletonList(content), "object", null,
                    null);
            dsc = new DOMSignContext(privateKey, signatureDoc);
            signature = sigFactory.newXMLSignature(si, ki, Collections.singletonList(xmlobj), null, null);
        } else {
            //TODO(AR) error, as below will cause NPE...
            dsc = null;
            signature = null;
        }

        dsc.setDefaultNamespacePrefix(signatureNamespacePrefix);

        // Marshal, generate and sign
        signature.sign(dsc);

        final DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
        final DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
        final LSSerializer serializer = impl.createLSSerializer();
        if (signatureType.equals("enveloping")) {
            return serializer.writeToString(signatureDoc);
        } else {
            return serializer.writeToString(sigParent);
        }
    }

    public static void main(final String[] args) throws ParserConfigurationException, SAXException, IOException,
            Exception {
        final String docString = "<data><a xml:id=\"type\"><b>23</b><c><d/></c></a></data>";
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);

        try (final Reader reader = new StringReader(docString)) {
            final Document inputDoc = dbf.newDocumentBuilder().parse(new InputSource(reader));

            final String[] certificateDetails = {
                    "JKS",
                    "ab987c",
                    "eXist",
                    "kpi135"
            };

            try (final InputStream is = Files.newInputStream(Paths.get("/home/claudius/mykeystoreEXist.ks"))) {

                final String domString = GenerateDigitalSignature(inputDoc, CanonicalizationMethod.EXCLUSIVE,
                        DigestMethod.SHA1, SignatureMethod.DSA_SHA1, "DSA", "ds", "enveloped", "//b",
                        certificateDetails, is);
                System.out.print(domString + "\n");
            }
        }
    }
}
