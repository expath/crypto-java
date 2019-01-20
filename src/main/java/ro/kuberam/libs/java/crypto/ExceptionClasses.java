package ro.kuberam.libs.java.crypto;

public enum ExceptionClasses {
	NoSuchProviderException(java.security.NoSuchProviderException.class.getCanonicalName()),
	NoSuchAlgorithmException(java.security.NoSuchAlgorithmException.class.getCanonicalName()),
	InvalidKeySpecException(java.security.spec.InvalidKeySpecException.class.getCanonicalName());
	
	private String canonicalName;

	ExceptionClasses(String canonicalName) {
    	this.canonicalName = canonicalName;
    }
}