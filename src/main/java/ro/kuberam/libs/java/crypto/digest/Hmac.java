package ro.kuberam.libs.java.crypto.digest;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
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

	public static String hmac(String data, String secretKey, String algorithm, String format)
			throws Exception {
		System.out.println("data = " + data);
		System.out.println("secretKey = " + secretKey);
		
		byte[] decodedData = null;
		byte[] decodedSecretKey = null;
		String result = null;

		try {
			decodedData = Base64.getDecoder().decode(data);
			decodedSecretKey = Base64.getDecoder().decode(secretKey);
		} catch (IllegalArgumentException e) {
			System.out.println("error ========= ");
		}
		System.out.println("decodedData = " + decodedData);
		System.out.println("decodedSecretKey = " + decodedSecretKey);
		System.out.println("======================== ");

		if (decodedData != null && decodedSecretKey == null) {
			result = hmac(decodedData, secretKey.getBytes(StandardCharsets.UTF_8), algorithm, format);
		}

		if (decodedData == null && decodedSecretKey != null) {
			result = hmac(data.getBytes(StandardCharsets.UTF_8), decodedSecretKey, algorithm, format);
		}

		if (decodedData != null && decodedSecretKey != null) {
			result = hmac(decodedData, decodedSecretKey, algorithm, format);
		}

		if (decodedData == null && decodedSecretKey == null) {
			result = hmac(data.getBytes(StandardCharsets.UTF_8), secretKey.getBytes(StandardCharsets.UTF_8), algorithm, format);
		}

		return result;
	}

	private static String hmac(byte[] data, byte[] secretKey, String algorithm, String format)
			throws Exception {

		// TODO: validate the format
		format = format.equals("") ? "base64" : format;
		System.out.println("format = " + format);

		StringBuffer sb = null;
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
			return Base64.getEncoder().encodeToString(resultBytes);
		} else {
			return DatatypeConverter.printHexBinary(resultBytes);
		}
	}
}
