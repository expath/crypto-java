package ro.kuberam.libs.java.crypto.digest;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.log4j.Logger;

import ro.kuberam.libs.java.crypto.ErrorMessages;
import ro.kuberam.libs.java.crypto.ExpathCryptoModule;

public class Hmac {

	private final static Logger logger = Logger.getLogger(Hmac.class);

	public static String hmac(byte[] data, byte[] secretKey, String algorithm, String format)
			throws Exception {
		String result;

		// TODO: validate the format
		format = format.equals("") ? "base64" : format;
		
		logger.debug("secretKey = " + secretKey);

		Mac mac = null;
		HashMap<String, String> javaStandardAlgorithmNames = ExpathCryptoModule.javaStandardAlgorithmNames;

		if (javaStandardAlgorithmNames.containsKey(algorithm)) {
			algorithm = javaStandardAlgorithmNames.get(algorithm);
		}

		SecretKeySpec signingKey = new SecretKeySpec(secretKey, algorithm);

		try {
			mac = Mac.getInstance(algorithm);
		} catch (NoSuchAlgorithmException ex) {
			throw new Exception(ErrorMessages.error_unknownAlgorithm);
		}

		try {
			mac.init(signingKey);
		} catch (InvalidKeyException ex) {
		}

		byte[] resultBytes = mac.doFinal(data);

		if (format.equals("base64")) {
			result = Base64.getEncoder().encodeToString(resultBytes);
		} else {
			result = DatatypeConverter.printHexBinary(resultBytes).toLowerCase();
		}
		logger.debug("result = " + result);
		
		return result;
	}
}
