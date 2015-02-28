/*
 *  eXist Java Cryptographic Extension
 *  Copyright (C) 2010 Claudius Teodorescu at http://kuberam.ro
 *
 *  Released under LGPL License - http://gnu.org/licenses/lgpl.html.
 *
 */
package ro.kuberam.libs.java.crypto.digitalSignature;

import java.security.Key;
import java.security.KeyException;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.List;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

/**
 * Cryptographic extension functions.
 * 
 * @author Claudius Teodorescu <claudius.teodorescu@gmail.com>
 */

public class ValidateXmlSignature {

	private final static Logger logger = Logger.getLogger(ValidateXmlSignature.class);

	public static Boolean validate(Document inputDoc) throws Exception {

		// Find Signature element
		logger.info("Claudius test: " + inputDoc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").getLength());
		//NodeList nl = inputDoc.getElementsByTagName("Signature");
		//NodeList nl = inputDoc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		
		XPathFactory factory = XPathFactory.newInstance();
		XPath xpath = factory.newXPath();
		// Find the node to be signed by PATH
		XPathExpression expr = xpath.compile("//*[local-name() = 'Signature' and namespace-uri() = '" + XMLSignature.XMLNS + "']");
		Node nl = (Node) expr.evaluate(inputDoc, XPathConstants.NODE);
		
//		if (nl.getLength() == 0) {
//			throw new XPathException(ErrorMessages.err_CX15);
//		}

		// Create a DOM XMLSignatureFactory that will be used to unmarshal the
		// document containing the XMLSignature
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
		logger.info("Claudius test: " + nl.getNodeName());
		// Create a DOMValidateContext and specify a KeyValue KeySelector
		// and document context
		DOMValidateContext valContext = new DOMValidateContext(new KeyValueKeySelector(), nl);
		
		// unmarshal the XMLSignature
		XMLSignature signature = fac.unmarshalXMLSignature(valContext);

		// Validate the XMLSignature (generated above)
		boolean coreValidity = signature.validate(valContext);

		// Check core validation status
		if (coreValidity == false) {
			System.err.println("Signature failed core validation");
			boolean sv = signature.getSignatureValue().validate(valContext);
			System.out.println("signature validation status: " + sv);
			// check the validation status of each Reference
			Iterator iterator = signature.getSignedInfo().getReferences().iterator();
			for (int j = 0; iterator.hasNext(); j++) {
				boolean refValid = ((Reference) iterator.next()).validate(valContext);
				System.out.println("ref[" + j + "] validity status: " + refValid);
			}
		}

		return coreValidity;
	}

	/**
	 * KeySelector which retrieves the public key out of the KeyValue element
	 * and returns it. NOTE: If the key algorithm doesn't match signature
	 * algorithm, then the public key will be ignored.
	 */
	private static class KeyValueKeySelector extends KeySelector {
		public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose, AlgorithmMethod method, XMLCryptoContext context)
				throws KeySelectorException {
			if (keyInfo == null) {
				throw new KeySelectorException("Null KeyInfo object!");
			}
			SignatureMethod sm = (SignatureMethod) method;
			List list = keyInfo.getContent();

			for (int i = 0; i < list.size(); i++) {
				XMLStructure xmlStructure = (XMLStructure) list.get(i);
				if (xmlStructure instanceof KeyValue) {
					PublicKey pk = null;
					try {
						pk = ((KeyValue) xmlStructure).getPublicKey();
					} catch (KeyException ke) {
						throw new KeySelectorException(ke);
					}
					// make sure algorithm is compatible with method
					if (algEquals(sm.getAlgorithm(), pk.getAlgorithm())) {
						return new SimpleKeySelectorResult(pk);
					}
				}
			}
			throw new KeySelectorException("No KeyValue element found!");
		}

		static boolean algEquals(String algURI, String algName) {
			if (algName.equalsIgnoreCase("DSA") && algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1)) {
				return true;
			} else if (algName.equalsIgnoreCase("RSA") && algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1)) {
				return true;
			} else {
				return false;
			}
		}
	}

	private static class SimpleKeySelectorResult implements KeySelectorResult {
		private PublicKey pk;

		SimpleKeySelectorResult(PublicKey pk) {
			this.pk = pk;
		}

		public Key getKey() {
			return pk;
		}
	}
}