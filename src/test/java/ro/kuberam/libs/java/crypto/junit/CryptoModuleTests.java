package ro.kuberam.libs.java.crypto.junit;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.util.UUID;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import com.fasterxml.uuid.Generators;
import com.fasterxml.uuid.impl.NameBasedGenerator;

import ro.kuberam.tests.junit.BaseTest;

public class CryptoModuleTests extends BaseTest {
	
	@Test
	public void test01() throws Exception {
		InputStream document = getClass().getResourceAsStream(
				"../doc-1.xml");
		InputStream digitalCertificate = getClass().getResourceAsStream(
				"../digital-certificate.xml");

		System.out.println(IOUtils.toString(digitalCertificate));
	}

	@Test
	public void pipedStreams1Test() throws Exception {
		final String message = "String for tests.";

		PipedInputStream in = new PipedInputStream();
		final PipedOutputStream outp = new PipedOutputStream(in);
		new Thread(new Runnable() {
			public void run() {
				try {
					outp.write(message.getBytes("UTF-8"));
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}).start();

		System.out.println("result: " + in);
	}

	@Test
	public void pipedStreams2Test() throws Exception {
		InputStream document = getClass().getResourceAsStream(
				"../doc-1.xml");
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		int next = document.read();
		while (next > -1) {
			bos.write(next);
			next = document.read();
		}
		bos.flush();
		byte[] result = bos.toByteArray();

		PipedOutputStream poStream = new PipedOutputStream();
		PipedInputStream piStream = new PipedInputStream();

		// piped input stream connect to the piped output stream
		piStream.connect(poStream);

		// Writes specified byte array.
		poStream.write(result);

		// Reads the next byte of data from this piped input stream.
		for (int i = 0; i < result.length; i++) {
			System.out.println(piStream.read());
		}

		// Closes piped input stream
		poStream.close();

		// Closes piped output stream
		piStream.close();
	}

	@Test
	public void digestOutputStreamTest() throws Exception {
		try {
			FileOutputStream fos = new FileOutputStream("/home/claudius/workspace-claudius/expath-crypto/src/org/expath/crypto/tests/string.txt");
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			DigestOutputStream dos = new DigestOutputStream(fos, md);
			ObjectOutputStream oos = new ObjectOutputStream(dos);
			String data = "This have I thought good to deliver thee, "+
				"that thou mightst not lose the dues of rejoicing " +
				"by being ignorant of what greatness is promised thee.";
			oos.writeObject(data);
			dos.on(false);
			byte[] digest = md.digest();
			oos.writeObject(digest);
			int digestLength = digest.length;
			System.out.println("length: " + digestLength);
		    BigInteger bi = new BigInteger(1, digest);
		    String result = bi.toString(digestLength);
		    if (result.length() % 2 != 0) {
		    	result = "0" + result;
		    }

			System.out.println("result: " + result);
		} catch (Exception e) {
			System.out.println(e);
		}
	}	public InputStream openStream() throws IOException {
		final PipedOutputStream out = new PipedOutputStream();
		PipedInputStream in = new PipedInputStream(out);

		Runnable exporter = new Runnable() {
			public void run() {
				try {
					out.write("message".getBytes("UTF-8"));
				} catch (UnsupportedEncodingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				IOUtils.closeQuietly(out);
			}
		};

		// executor.submit(exporter);

		return in;
	}
	
	@Test
	public void uuid5Test() throws Exception {
		
		String seed = "www.widgets.com";
		
		NameBasedGenerator uuid_gen_dns = Generators.nameBasedGenerator(NameBasedGenerator.NAMESPACE_DNS);
		UUID uuid_dns = uuid_gen_dns.generate(seed);
		System.out.println("uuid_dns: " + uuid_dns);
	
		NameBasedGenerator uuid_gen_oid = Generators.nameBasedGenerator(NameBasedGenerator.NAMESPACE_OID);
		UUID uuid_oid = uuid_gen_oid.generate(seed);
		System.out.println("uuid_oid: " + uuid_oid);
		
		NameBasedGenerator uuid_gen_url = Generators.nameBasedGenerator(NameBasedGenerator.NAMESPACE_URL);
		UUID uuid_url = uuid_gen_url.generate(seed);
		System.out.println("uuid_url: " + uuid_url);
		
		NameBasedGenerator uuid_gen_x500 = Generators.nameBasedGenerator(NameBasedGenerator.NAMESPACE_X500);
		UUID uuid_x500 = uuid_gen_x500.generate(seed);
		System.out.println("uuid_x500: " + uuid_x500);		
		
	}	
	
	@Test
	public void uuid5NewTest() throws Exception {
	String NameSpace_OID_string = "6ba7b812-9dad-11d1-80b4-00c04fd430c8";
	UUID NameSpace_OID_uuid = UUID.fromString(NameSpace_OID_string);

	long msb = NameSpace_OID_uuid.getMostSignificantBits();
	long lsb = NameSpace_OID_uuid.getLeastSignificantBits();

	    byte[] NameSpace_OID_buffer = new byte[16];

	    for (int i = 0; i < 8; i++) {
	        NameSpace_OID_buffer[i] = (byte) (msb >>> 8 * (7 - i));
	    }
	    for (int i = 8; i < 16; i++) {
	        NameSpace_OID_buffer[i] = (byte) (lsb >>> 8 * (7 - i));
	    }

	    String name = "user123";
	    byte[] name_buffer = name.getBytes();

	ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
	try {
	    outputStream.write( NameSpace_OID_buffer);
	    outputStream.write( name_buffer );
	} catch (IOException e) {
	        // TODO Auto-generated catch block
	    e.printStackTrace();
	}


	byte byteArray[] = outputStream.toByteArray();

	System.out.println(UUID.nameUUIDFromBytes(byteArray).toString());
}
	public static void main(String[] args) throws Exception {

	}

}
