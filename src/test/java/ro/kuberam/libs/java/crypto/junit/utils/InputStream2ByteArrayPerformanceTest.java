package ro.kuberam.libs.java.crypto.junit.utils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class InputStream2ByteArrayPerformanceTest extends BaseTest {

	private static File tempFile;
	private static InputStream tempFileIs;

	@Before
	public void initialize() throws IOException {
		tempFile = generate5MbTempFile();
		tempFileIs = new FileInputStream(tempFile);

	}

	@Test
	public void byteArrayOutputStreamTest() throws Exception {

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		int next = tempFileIs.read();
		while (next > -1) {
			baos.write(next);
			next = tempFileIs.read();
		}
		baos.flush();
		byte[] byteArray = baos.toByteArray();

		Assert.assertTrue(byteArray.length == 5200000);
	}

}
