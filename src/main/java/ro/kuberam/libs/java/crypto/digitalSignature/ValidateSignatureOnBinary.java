package ro.kuberam.libs.java.crypto.digitalSignature;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import ro.kuberam.libs.java.crypto.keyManagement.GenerateKeyPair;

public class ValidateSignatureOnBinary {

    public static byte[] generateSignatureOnBinary(final byte[] data,
                                                   final PrivateKey privateKey, final String algorithm) throws Exception {
        final Signature dsa = Signature.getInstance(algorithm);
        dsa.initSign(privateKey);
        dsa.update(data);
        return dsa.sign();
    }

    public static boolean validateSignatureOnBinary(final byte[] data, final PublicKey publicKey, final byte[] signature, final String algorithm)
            throws Exception {
        final Signature signer = Signature.getInstance(algorithm);
        signer.initVerify(publicKey);
        signer.update(data);
        return signer.verify(signature);

    }

    public static void main(final String args[]) throws Exception {
        final KeyPair keyPair = GenerateKeyPair.generate(1008, "SHA1PRNG",
                "base64");

        final byte[] data = {65, 66, 67, 68, 69, 70, 71, 72, 73, 74};
        final boolean validate = validateSignatureOnBinary(data,
                keyPair.getPublic(), null, "SHA1withDSA");

        System.out.println("Validate:\n" + validate);
    }

}
