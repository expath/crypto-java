package ro.kuberam.libs.java.crypto;

public class ErrorMessages {
    public static final String error_unknownAlgorithm = "crypto:unknown-algorithm: The specified algorithm is not supported.";
    public static final String error_signatureType = "crypto:signature-type: The specified signature type is not supported.";
    public static final String error_readKeystore = "crypto:unreadable-keystore: I/O error while reading keystore, or the password is incorrect.";
    public static final String error_deniedKeystore = "crypto:denied-keystore: Permission denied to read keystore.";
    public static final String error_keystoreUrl = "crypto:keystore-url: The keystore URL is invalid.";
    public static final String error_keystoreType = "crypto:keystore-type: The keystore type is not supported.";
    public static final String error_aliasKey = "crypto:alias-key: Cannot find key for alias in given keystore.";
    public static final String error_invalidKey = "crypto:invalid-key: The specified key is invalid.";
    public static final String error_sigElem = "crypto:signature-element: Cannot find Signature element.";
    public static final String error_noPadding = "crypto:inexistent-padding: No such padding.";
    public static final String error_incorrectPadding = "crypto:incorrect-padding: Incorrect padding.";
    public static final String error_encType = "crypto:encryption-type: The encryption type is not supported.";
    public static final String error_cryptoKey = "crypto:invalid-crypto-key: The cryptographic key is invalid.";
    public static final String error_blockSize = "crypto:block-size: Illegal block size.";
    public static final String error_decryptionType = "crypto:decryption-type: The decryption type is not supported.";
    public static final String error_noProvider = "crypto:no-provider: The provider is not set.";
    public static final String error_outputFormat = "crypto.output-format: The output format is not supported.";
}