package ro.kuberam.libs.java.crypto.keyManagement;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;
import java.util.regex.Pattern;

public class Load {
	private static Pattern pattern = Pattern.compile("(?m)(?s)^---*BEGIN.*---*$(.*)^---*END.*---*$.*");

	public static PublicKey publicKey(String base64PublicKey, String algorithm, String provider)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		provider = Optional.ofNullable(provider).filter(str -> !str.isEmpty()).orElse("SunRsaSign");
		String cleanedKey = cleanKey(base64PublicKey);

		X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getMimeDecoder().decode(cleanedKey));
		KeyFactory kf = KeyFactory.getInstance(algorithm, provider);

		return kf.generatePublic(spec);
	}

	public static PrivateKey privateKey(String base64PrivateKey, String algorithm, String provider)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		provider = Optional.ofNullable(provider).filter(str -> !str.isEmpty()).orElse("SunRsaSign");
		String cleanedKey = cleanKey(base64PrivateKey);

		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(cleanedKey));

		KeyFactory kf = KeyFactory.getInstance(algorithm, provider);

		return kf.generatePrivate(keySpec);
	}

	private static String cleanKey(String base64Key) {
		return pattern.matcher(base64Key).replaceFirst("$1");
	}

}
