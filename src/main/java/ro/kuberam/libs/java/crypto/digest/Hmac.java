package ro.kuberam.libs.java.crypto.digest;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ro.kuberam.libs.java.crypto.ErrorMessages;
import ro.kuberam.libs.java.crypto.ExpathCryptoModule;

public class Hmac {

    private static final Logger LOG = LogManager.getLogger(Hmac.class);

    public static String hmac(final byte[] data, final byte[] secretKey, final String algorithm, @Nullable final String format) throws Exception {

        // TODO: validate the format
        final String actualFormat = Optional.ofNullable(format)
                .filter(str -> !str.isEmpty())
                .orElse("base64");    // default to Base64

        if (LOG.isDebugEnabled()) {
            LOG.debug("secretKey = " + secretKey);
        }

        final byte[] resultBytes = hmac(data, secretKey, algorithm);

        final String result;
        if (actualFormat.equals("base64")) {
            result = Base64.getEncoder().encodeToString(resultBytes);
        } else {
            result = DatatypeConverter.printHexBinary(resultBytes).toLowerCase();
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("result = " + result);
        }

        return result;
    }

    public static byte[] hmac(final byte[] data, final byte[] secretKey, String algorithm) throws Exception {
        final Map<String, String> javaStandardAlgorithmNames = ExpathCryptoModule.javaStandardAlgorithmNames;

        if (javaStandardAlgorithmNames.containsKey(algorithm)) {
            algorithm = javaStandardAlgorithmNames.get(algorithm);
        }

        final SecretKeySpec signingKey = new SecretKeySpec(secretKey, algorithm);

        try {
            final Mac mac = Mac.getInstance(algorithm);
            mac.init(signingKey);
            return mac.doFinal(data);

        } catch (final NoSuchAlgorithmException ex) {
            throw new Exception(ErrorMessages.error_unknownAlgorithm);
        } catch (final InvalidKeyException ex) {
            throw new Exception(ErrorMessages.error_invalidKey);
        }
    }
}
