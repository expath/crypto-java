package ro.kuberam.libs.java.crypto.digitalSignature;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;

import org.junit.Test;

import ro.kuberam.libs.java.crypto.keyManagement.Load;

public class GenerateSignatureForStringTest {

	@Test
	public void JWT() throws Exception {
		String input = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
		String sampleOutput = "POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA";

		String algorithm = "RSA";
		String base64PrivateKey = new String(
				Files.readAllBytes(Paths.get(getClass().getResource("../JWT-private-key.pkcs8").toURI())), UTF_8);
		PrivateKey privateKey = Load.privateKey(base64PrivateKey, algorithm, null);

		String output = SignatureForString.generate(input, privateKey, "SHA256withRSA");
		output = output.replace("/", "_").replaceAll("=", "").replaceAll("\\+", "-");

		assertEquals(output, sampleOutput);
	}
}
