package ro.kuberam.libs.java.crypto.junit.utils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Formatter;

import javax.xml.bind.annotation.adapters.HexBinaryAdapter;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

public class ByteArray2HexStringPerformanceTest extends BaseTest {

	private static File tempFile;
	private static byte[] tempByteArray;

	@BeforeClass
	public static void initialize() throws IOException {
		tempFile = generate5MbTempFile();
		InputStream is = new FileInputStream(tempFile);
		
		//
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		int next = is.read();
		while (next > -1) {
		    bos.write(next);
		    next = is.read();
		}
		bos.flush();		
		tempByteArray = bos.toByteArray();
	}

	
	@Test
	public void hexCharsTest() throws Exception {

		final char[] HEX_CHARS = "0123456789abcdef".toCharArray();
		
		int tempByteArrayLength = tempByteArray.length;

		char[] chars = new char[2 * tempByteArrayLength];
        for (int i = 0; i < tempByteArrayLength; ++i)
        {
            chars[2 * i] = HEX_CHARS[(tempByteArray[i] & 0xF0) >>> 4];
            chars[2 * i + 1] = HEX_CHARS[tempByteArray[i] & 0x0F];
        }
        String result = new String(chars);
        Assert.assertTrue(result.length() == 10400000);
	}	

	@Test
	public void formatterTest() throws Exception {

		Formatter formatter = new Formatter();
		for (byte b : tempByteArray) {
			formatter.format("%02x", b);
		}

		String result = formatter.toString();
		Assert.assertTrue(result.length() == 10400000);
	}
	
	@Test
	public void stringBufferTest1() throws Exception {
		
		int tempByteArrayLength = tempByteArray.length;

		StringBuffer strbuf = new StringBuffer(tempByteArrayLength * 2);

        for(int i=0; i< tempByteArrayLength; i++)
        {
                if(((int) tempByteArray[i] & 0xff) < 0x10)
                        strbuf.append("0");
                strbuf.append(Long.toString((int) tempByteArray[i] & 0xff, 16));
        }

		String result = strbuf.toString();
		Assert.assertTrue(result.length() == 10400000);
	}
	
	@Test
	public void stringBufferTest2() throws Exception {
		
		StringBuffer sb = new StringBuffer();
		for (byte b : tempByteArray) {
			sb.append(Integer.toHexString((int) (b & 0xff)));
		}

		String result = sb.toString();
		Assert.assertTrue(result.length() == 10400000);
	}
	
	@Test
	public void charArrayTest() throws Exception {
		
		char[] hexDigits = "0123456789abcdef".toCharArray();
		char[] byteToHexPair = new char[16 * 16 * 2];
		for (int i = 0, o = 0; i < 256; ++i) {
			byteToHexPair[o++] = hexDigits[i >>> 4];
		    byteToHexPair[o++] = hexDigits[i & 15];
		}
		
		int tempByteArrayLength = tempByteArray.length;
		  char[] chars = new char[2 * tempByteArrayLength];
		  for (int i = 0, o = 0; i < tempByteArrayLength; ++i) {
		    int index = tempByteArray[i];
		    chars[o++] = byteToHexPair[index++];
		    chars[o++] = byteToHexPair[index];
		  }

		String result = new String(chars);
		Assert.assertTrue(result.length() == 10400000);
	}
	
	@Test
	public void hexArrayTest() throws Exception {
		
		int tempByteArrayLength = tempByteArray.length;
		
		char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
		char[] hexChars = new char[tempByteArrayLength * 2];
		int v;
		for ( int j = 0; j < tempByteArrayLength; j++ ) {
			v = tempByteArray[j] & 0xFF;
			hexChars[j*2] = hexArray[v/16];
			hexChars[j*2 + 1] = hexArray[v%16];
		}
		 
		String result = new String(hexChars);
		Assert.assertTrue(result.length() == 10400000);
	}
	
	@Test
	public void stringBuilder1Test() throws Exception {
		
		StringBuilder sb = new StringBuilder();
	    for (byte b : tempByteArray) {
	        sb.append(String.format("%1$02X", b));
	    }
		 
		String result = sb.toString();
		Assert.assertTrue(result.length() == 10400000);
	}	
	
	@Test
	public void stringBuilder2Test() throws Exception {
		
		int tempByteArrayLength = tempByteArray.length;
		
	    StringBuilder sb = new StringBuilder(tempByteArrayLength*2);
	    for(byte b: tempByteArray) {
	    	sb.append(Integer.toHexString(b+0x800).substring(1));
	    }
	    
		String result = sb.toString();
		Assert.assertTrue(result.length() == 10400000);
	}
	
	@Test
	public void stringBuilder3Test() throws Exception {
		
		int tempByteArrayLength = tempByteArray.length;
		
		String digits = "0123456789abcdef";
		
		StringBuilder sb = new StringBuilder(tempByteArrayLength * 2);
		for (byte b : tempByteArray) {
			int bi = b & 0xff;
			sb.append(digits.charAt(bi >> 4));
			sb.append(digits.charAt(bi & 0xf));
		}
	    
		String result = sb.toString();
		Assert.assertTrue(result.length() == 10400000);
	}
	
	@Test
	public void stringBuilder4Test() throws Exception {
		
		int tempByteArrayLength = tempByteArray.length;
		
		StringBuffer hexString = new StringBuffer();
		for (int i = 0; i < tempByteArrayLength; i++) {
		    String hexByte = Integer.toHexString(0xFF & tempByteArray[i]);
		    int numDigits = 2 - hexByte.length();
		    while (numDigits-- > 0) {
		        hexString.append('0');
		    }
		    hexString.append(hexByte);
		}

		String result = hexString.toString();
		Assert.assertTrue(result.length() == 10400000);
	}
	
	@Test
	public void hexBinaryAdapterTest() throws Exception {
		
		String result = (new HexBinaryAdapter()).marshal(tempByteArray);

		Assert.assertTrue(result.length() == 10400000);
	}
	
	@Test
	public void integer2Test() throws Exception {
		
		int tempByteArrayLength = tempByteArray.length;
		
		StringBuffer hexString = new StringBuffer();

		for (int i = 0; i < tempByteArrayLength; i++) {
		    int temp=0xFF & tempByteArray[i];
		    String s=Integer.toHexString(temp);
		    if(temp<=0x0F){
		        s="0"+s;
		    }
		    hexString.append(s);
		}
		
		String result = hexString.toString();
		Assert.assertTrue(result.length() == 10400000);
	}	
	
	@Test
	@Ignore("too slow, took hours and didn't finish")	
	public void integer1Test() throws Exception {
		
		int tempByteArrayLengthQuartered = tempByteArray.length / 4;

		String result = "";
		for(int i = 0; i < tempByteArrayLengthQuartered; i++){
		  int ii = i * 4;
		  int inty = tempByteArray[ii] + tempByteArray[ii+1]*0xff + tempByteArray[ii+2]*0xffff + tempByteArray[ii+3]*0xffffff;
		  result = Integer.toHexString(inty) + result;
		}

		Assert.assertTrue(result.length() == 10400000);
	}
	
	@Test
	@Ignore("too slow")
	public void stringFormatterTest() throws Exception {
		
		byte[] a = { 0x40, 0x00, 0x39, 0x00 };

		String result = String.format("%0128x", new BigInteger(1, tempByteArray));
	}

}
