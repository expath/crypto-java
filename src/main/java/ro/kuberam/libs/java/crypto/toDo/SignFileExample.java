package ro.kuberam.libs.java.crypto.toDo;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
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
    private static final String KEY_STORE_TYPE = "JKS";
    private static final String KEY_STORE_NAME = "/home/claudius/mykeystoreEXist.ks";
    private static final String KEY_STORE_PASS = "ab987c";
    private static final String PRIVATE_KEY_PASS = "kpi135";
    private static final String KEY_ALIAS = "eXist";

    private static final String PATH = "/PatientRecord/Account";
    private static final String ID = "acct";

    private static enum SignatureType {
	SIGN_BY_ID,
	SIGN_BY_PATH,
	SIGN_WHOLE_DOCUMENT
    };

    public static void main(String[] args) throws Exception {
        /*if (args.length < 2) {
        usage();
        return;
        }*/

	String inputFile = "doc.xml";
	String outputFile = "doc-signed.xml";

	SignatureType sigType = SignatureType.SIGN_WHOLE_DOCUMENT;
	if (args.length >= 3) {
	    if ("id".equals(args[2])) {
		sigType = SignatureType.SIGN_BY_ID;
	    }
	    else if ("path".equals(args[2])) {
		sigType = SignatureType.SIGN_BY_PATH;
	    }
	}

	// Instantiate the document to be signed
	DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
	dbFactory.setNamespaceAware(true);
	Document doc = dbFactory
		       .newDocumentBuilder()
		       .parse(new FileInputStream(inputFile));

	// prepare signature factory
        String providerName = System.getProperty(
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

	XPathFactory factory = XPathFactory.newInstance();
	XPath xpath = factory.newXPath();
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
	KeyStore keyStore = KeyStore.getInstance( KEY_STORE_TYPE );
	keyStore.load( new FileInputStream(KEY_STORE_NAME), KEY_STORE_PASS.toCharArray() );

	PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, PRIVATE_KEY_PASS.toCharArray() );

	X509Certificate cert = (X509Certificate) keyStore.getCertificate(KEY_ALIAS);
	PublicKey publicKey = cert.getPublicKey();

        // Create a KeyValue containing the RSA PublicKey
	KeyInfoFactory keyInfoFactory = sigFactory.getKeyInfoFactory();
        KeyValue keyValue = keyInfoFactory.newKeyValue(publicKey);

	// Create a KeyInfo and add the KeyValue to it
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(keyValue));



        


        // Create a Reference to the enveloped document
	Reference ref = sigFactory.newReference(
			    referenceURI,
			    sigFactory.newDigestMethod(DigestMethod.SHA1, null),
			    transforms,
			    null,
			    null
			);

	// Create the SignedInfo
	SignedInfo signedInfo = sigFactory.newSignedInfo(
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
	DOMSignContext dsc = new DOMSignContext(
				 privateKey,
				 sigParent
			     );

	// Create the XMLSignature (but don't sign it yet)
	XMLSignature signature = sigFactory.newXMLSignature(signedInfo, keyInfo);

        // Marshal, generate (and sign) the enveloped signature
        signature.sign(dsc);

	// output the resulting document
	OutputStream os = new FileOutputStream(args[1]);
	Transformer trans = TransformerFactory.newInstance().newTransformer();
	trans.transform(new DOMSource(doc), new StreamResult(os));
    }

    private static void usage() {
	System.out.println("Usage: java SignFile <inputFile> <outputFile> [id|path|whole]");
    }
}

