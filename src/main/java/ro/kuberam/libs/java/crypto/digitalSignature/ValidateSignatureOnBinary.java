package ro.kuberam.libs.java.crypto.digitalSignature;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import ro.kuberam.libs.java.crypto.keyManagement.GenerateKeyPair;

public class ValidateSignatureOnBinary {

	public static byte[] generateSignatureOnBinary(byte[] data,
			PrivateKey privateKey, String algorithm) throws Exception {
		Signature dsa = Signature.getInstance(algorithm);
		dsa.initSign(privateKey);
		dsa.update(data);
		byte[] signature = dsa.sign();
		return signature;
	}

	public static boolean validateSignatureOnBinary(byte[] data, PublicKey publicKey, byte[] signature, String algorithm)
			throws Exception {
		Signature signer = Signature.getInstance(algorithm);
		signer.initVerify(publicKey);
		signer.update(data);
		return (signer.verify(signature));

	}

	public static void main(String args[]) throws Exception {

		KeyPair keyPair = GenerateKeyPair.generateKeyPair(1008, "SHA1PRNG",
				"base64");

		byte[] data = { 65, 66, 67, 68, 69, 70, 71, 72, 73, 74 };
		boolean validate = validateSignatureOnBinary(data,
				keyPair.getPublic(), null, "SHA1withDSA");

		System.out.println("Validate:\n" + validate);
	}

}
