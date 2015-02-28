package ro.kuberam.libs.java.crypto.junit.digest;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.DigestInputStream;
import java.security.MessageDigest;

import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.Assert;

import ro.kuberam.tests.junit.BaseTest;

public class HashPerformanceTest extends BaseTest {
	
	private static File tempFile;
	private static InputStream tempFileIs;	
	private static byte[] tempBa;
	private static String tempString;

	@BeforeClass
	public static void initialize() throws IOException {
		tempFile = generate5MbTempFile();
		tempFileIs = new FileInputStream(tempFile);
		
		//
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		int next = tempFileIs.read();
		while (next > -1) {
		    bos.write(next);
		    next = tempFileIs.read();
		}
		bos.flush();		
		tempBa = bos.toByteArray();
		
		tempString = generate5MbTempString();
	}

	@Test
	public void digestInputStreamWithFileInputStreamTest() throws Exception {

		MessageDigest algorithm = MessageDigest.getInstance("SHA");
		DigestInputStream dis = new DigestInputStream(tempFileIs, algorithm);

		// read the file and update the hash calculation
		while (dis.read() != -1)
			;

		// get the hash value as byte array
		byte[] hash = algorithm.digest();
		
		Assert.assertTrue(hash.length == 20);
	}
	
	@Test
	public void digestInputStreamWithBufferedInputStreamTest() throws Exception {

		BufferedInputStream bis = new BufferedInputStream(tempFileIs);
		MessageDigest algorithm = MessageDigest.getInstance("SHA");
		DigestInputStream dis = new DigestInputStream(bis, algorithm);

		// read the file and update the hash calculation
		while (dis.read() != -1)
			;

		// get the hash value as byte array
		byte[] hash = algorithm.digest();
		
		Assert.assertTrue(hash.length == 20);
	}
	
	@Test
	public void digestStringWithInputStreamTest() throws Exception {
		
		InputStream is = null;
		
        try {
            is = new ByteArrayInputStream(tempString.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
		
		MessageDigest algorithm = MessageDigest.getInstance("SHA");
		DigestInputStream dis = new DigestInputStream(is, algorithm);

		// read the file and update the hash calculation
		while (dis.read() != -1)
			;

		// get the hash value as byte array
		byte[] hash = algorithm.digest();
		
		Assert.assertTrue(hash.length == 20);
	}
	
	@Test
	public void digestString() throws Exception {
		
		MessageDigest algorithm = MessageDigest.getInstance("SHA");
		algorithm.update(tempString.getBytes("UTF-8"));
		byte[] hash = algorithm.digest();
		
		Assert.assertTrue(hash.length == 20);
	}	
	
	@Test
	@Ignore("too slow")
	public void digestWithByteArrayOutputStreamTest() throws Exception {
		
		int tempByteArrayLength = tempBa.length;
		MessageDigest algorithm = MessageDigest.getInstance("SHA");
		
		while (tempByteArrayLength > 0) {
			algorithm.update(tempBa, 0, tempByteArrayLength);
			tempByteArrayLength = tempBa.length;
		}

		// get the hash value as byte array
		byte[] hash = algorithm.digest();
		
		Assert.assertTrue(hash.length == 20);
	}	

}
