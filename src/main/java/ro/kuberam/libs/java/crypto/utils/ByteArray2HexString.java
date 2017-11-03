package ro.kuberam.libs.java.crypto.utils;

public class ByteArray2HexString {

    public String convert(final byte[] byteArray) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < byteArray.length; ++i) {
            sb.append(Integer.toHexString((byteArray[i] & 0xFF) | 0x100).substring(1, 3));
        }
        return sb.toString();
    }
}
//TODO: make this work with large byte arrays, maybe with a pipeline 