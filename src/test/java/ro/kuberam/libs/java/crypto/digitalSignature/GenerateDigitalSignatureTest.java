package ro.kuberam.libs.java.crypto.digitalSignature;

import java.io.File;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;

import ro.kuberam.libs.java.crypto.Parameters;
import ro.kuberam.tests.junit.BaseTest;

public class GenerateDigitalSignatureTest extends BaseTest {

	@Test
	public void generateEnvelopedDigitalSignature() throws Exception {
		Parameters parameters = new Parameters();
		parameters.setSignatureType("enveloping");
		List<Document> data = new ArrayList<Document>();
		DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();

		Document doc1 = docBuilder.parse(new File(
				"src/test/resources/ro/kuberam/libs/java/crypto/digitalSignature/doc-1.xml"));
		data.add(doc1);

		Document doc2 = docBuilder.parse(new File(
				"src/test/resources/ro/kuberam/libs/java/crypto/digitalSignature/doc-2.xml"));
		data.add(doc2);

		Document doc3 = docBuilder.parse(new File(
				"src/test/resources/ro/kuberam/libs/java/crypto/digitalSignature/doc-3.xml"));
		data.add(doc3);

		generateXMLSignature(data, parameters);
	}

	private String generateXMLSignature(List<Document> data, Parameters parameters)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

		String keyPairAlgorithm = "RSA";

		final XMLSignatureFactory sigFactory = XMLSignatureFactory.getInstance("DOM");

		// create references
		ArrayList<Reference> references = new ArrayList<Reference>();
		List<XMLObject> xmlObjects = new ArrayList<XMLObject>();

		Iterator<Document> iterator = data.iterator();
		while (iterator.hasNext()) {
			Document referencedObject = (Document) iterator.next();
			List<Transform> transforms = Collections.singletonList(sigFactory.newTransform(
					Transform.ENVELOPED, (TransformParameterSpec) null));
			Reference reference = sigFactory.newReference("",
					sigFactory.newDigestMethod(parameters.getDigestAlgorithm(), null), transforms, null,
					null);
			references.add(reference);

			xmlObjects.add(sigFactory.newXMLObject(
					Collections.singletonList(new DOMStructure(referencedObject.getDocumentElement())),
					null, null, null));
		}

		SignedInfo si = sigFactory.newSignedInfo(sigFactory.newCanonicalizationMethod(
				parameters.getCanonicalizationAlgorithm(), (C14NMethodParameterSpec) null), sigFactory
				.newSignatureMethod(parameters.getSignatureAlgorithm(), null), references);

		// to be removed==============================
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyPairAlgorithm);
		kpg.initialize(512);
		KeyPair kp = kpg.generateKeyPair();
		KeyInfoFactory kif = sigFactory.getKeyInfoFactory();
		KeyValue kv = null;
		try {
			kv = kif.newKeyValue(kp.getPublic());
		} catch (KeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));
		PrivateKey privateKey = kp.getPrivate();
		// to be removed==============================

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		Document doc = null;
		try {
			doc = dbf.newDocumentBuilder().newDocument();
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		DOMSignContext dsc = new DOMSignContext(privateKey, doc);

		XMLSignature signature = sigFactory.newXMLSignature(si, ki, xmlObjects, null, null);

		try {
			signature.sign(dsc);
		} catch (MarshalException | XMLSignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		DOMImplementationRegistry registry = null;
		try {
			registry = DOMImplementationRegistry.newInstance();
		} catch (ClassNotFoundException | InstantiationException | IllegalAccessException
				| ClassCastException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
		LSSerializer serializer = impl.createLSSerializer();
		System.out.println(serializer.writeToString(doc));

		return "";
	}
}
