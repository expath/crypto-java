package ro.kuberam.libs.java.crypto.keyManagement;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class LoadPrivateKey {
	public static PrivateKey run(String base64PrivateKey, String algorithm, String provider)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		// provider = Optional.ofNullable(provider).filter(str ->
		// !str.isEmpty()).orElse("SunRsaSign");
		provider = "SunRsaSign";

		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(
				Base64.getDecoder().decode(base64PrivateKey.getBytes(UTF_8)));

		KeyFactory kf = KeyFactory.getInstance(algorithm, provider);

		return kf.generatePrivate(keySpec);
	}
}
