package ro.kuberam.libs.java.crypto.digitalSignature;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import ro.kuberam.libs.java.crypto.keyManagement.GenerateKeyPair;

public class GenerateSignatureOnBinary {

	public static byte[] generateSignatureOnBinary(byte[] data,
			PrivateKey privateKey, String algorithm) throws Exception {
		Signature dsa = Signature.getInstance(algorithm);
		dsa.initSign(privateKey);
		dsa.update(data);
		byte[] signature = dsa.sign();
		return signature;
	}

	public static boolean verifySig(byte[] data, PublicKey key, byte[] sig)
			throws Exception {
		Signature signer = Signature.getInstance("SHA1withDSA");
		signer.initVerify(key);
		signer.update(data);
		return (signer.verify(sig));

	}

	public static void main(String args[]) throws Exception {

		KeyPair keyPair = GenerateKeyPair.generateKeyPair(1008, "SHA1PRNG",
				"base64");

		byte[] data = { 65, 66, 67, 68, 69, 70, 71, 72, 73, 74 };
		byte[] signature = generateSignatureOnBinary(data,
				keyPair.getPrivate(), "SHA1withDSA");

		System.out.println("Signature:\n" + new String(signature));
	}

}
