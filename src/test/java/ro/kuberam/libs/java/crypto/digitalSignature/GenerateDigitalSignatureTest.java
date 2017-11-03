package ro.kuberam.libs.java.crypto.digitalSignature;

import java.nio.file.Paths;
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
        final Parameters parameters = new Parameters();
        parameters.setSignatureType("enveloping");
        final List<Document> data = new ArrayList<>();
        final DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        final DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();

        final Document doc1 = docBuilder.parse(Paths.get(
                "src/test/resources/ro/kuberam/libs/java/crypto/digitalSignature/doc-1.xml").toFile());
        data.add(doc1);

        final Document doc2 = docBuilder.parse(Paths.get(
                "src/test/resources/ro/kuberam/libs/java/crypto/digitalSignature/doc-2.xml").toFile());
        data.add(doc2);

        final Document doc3 = docBuilder.parse(Paths.get(
                "src/test/resources/ro/kuberam/libs/java/crypto/digitalSignature/doc-3.xml").toFile());
        data.add(doc3);

        generateXMLSignature(data, parameters);
    }

    private String generateXMLSignature(final List<Document> data, final Parameters parameters)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyException, ParserConfigurationException, MarshalException, XMLSignatureException, InstantiationException, IllegalAccessException, ClassNotFoundException {

        final String keyPairAlgorithm = "RSA";

        final XMLSignatureFactory sigFactory = XMLSignatureFactory.getInstance("DOM");

        // create references
        final List<Reference> references = new ArrayList<>();
        final List<XMLObject> xmlObjects = new ArrayList<>();

        final Iterator<Document> iterator = data.iterator();
        while (iterator.hasNext()) {
            final Document referencedObject = iterator.next();
            final List<Transform> transforms = Collections.singletonList(sigFactory.newTransform(
                    Transform.ENVELOPED, (TransformParameterSpec) null));
            final Reference reference = sigFactory.newReference("",
                    sigFactory.newDigestMethod(parameters.getDigestAlgorithm(), null), transforms, null,
                    null);
            references.add(reference);

            xmlObjects.add(sigFactory.newXMLObject(
                    Collections.singletonList(new DOMStructure(referencedObject.getDocumentElement())),
                    null, null, null));
        }

        final SignedInfo si = sigFactory.newSignedInfo(sigFactory.newCanonicalizationMethod(
                parameters.getCanonicalizationAlgorithm(), (C14NMethodParameterSpec) null), sigFactory
                .newSignatureMethod(parameters.getSignatureAlgorithm(), null), references);

        // to be removed==============================
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyPairAlgorithm);
        kpg.initialize(512);
        final KeyPair kp = kpg.generateKeyPair();
        final KeyInfoFactory kif = sigFactory.getKeyInfoFactory();
        final KeyValue kv = kif.newKeyValue(kp.getPublic());

        final KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));
        final PrivateKey privateKey = kp.getPrivate();
        // to be removed==============================

        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        final Document doc = dbf.newDocumentBuilder().newDocument();

        final DOMSignContext dsc = new DOMSignContext(privateKey, doc);

        final XMLSignature signature = sigFactory.newXMLSignature(si, ki, xmlObjects, null, null);
        signature.sign(dsc);

        final DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
        final DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
        final LSSerializer serializer = impl.createLSSerializer();
        System.out.println(serializer.writeToString(doc));

        return "";
    }
}
