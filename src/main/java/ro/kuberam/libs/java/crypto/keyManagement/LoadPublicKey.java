package ro.kuberam.libs.java.crypto.keyManagement;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class LoadPublicKey {

	public static PublicKey run(String base64PublicKey, String algorithm, String provider)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		// provider = Optional.ofNullable(provider).filter(str ->
		// !str.isEmpty()).orElse("SunRsaSign");
		provider = "SunRsaSign";

		X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes(UTF_8)));
		KeyFactory kf = KeyFactory.getInstance(algorithm, provider);

		return kf.generatePublic(spec);
	}

}
