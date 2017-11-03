package ro.kuberam.libs.java.crypto.digitalSignature;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import ro.kuberam.libs.java.crypto.keyManagement.GenerateKeyPair;

public class GenerateSignatureOnBinary {

    public static byte[] generateSignatureOnBinary(final byte[] data,
                                                   final PrivateKey privateKey, final String algorithm) throws Exception {
        final Signature dsa = Signature.getInstance(algorithm);
        dsa.initSign(privateKey);
        dsa.update(data);
        return dsa.sign();
    }

    public static boolean verifySig(final byte[] data, final PublicKey key, final byte[] sig)
            throws Exception {
        final Signature signer = Signature.getInstance("SHA1withDSA");
        signer.initVerify(key);
        signer.update(data);
        return signer.verify(sig);

    }

    public static void main(final String args[]) throws Exception {

        final KeyPair keyPair = GenerateKeyPair.generate(1008, "SHA1PRNG",
                "base64");

        final byte[] data = {65, 66, 67, 68, 69, 70, 71, 72, 73, 74};
        final byte[] signature = generateSignatureOnBinary(data,
                keyPair.getPrivate(), "SHA1withDSA");

        System.out.println("Signature:\n" + new String(signature));
    }

}
