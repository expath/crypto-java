/**
 * EXPath Cryptographic Module
 * Java Library providing an EXPath Cryptographic Module
 * Copyright (C) 2015 Kuberam
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
package ro.kuberam.libs.java.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.util.UUID;

import org.apache.commons.io.IOUtils;
import org.junit.Ignore;
import org.junit.Test;

import com.fasterxml.uuid.Generators;
import com.fasterxml.uuid.impl.NameBasedGenerator;

public class UtilsTests extends CryptoModuleTests {

    @Test
    public void pipedStreams1Test() throws Exception {
        final String message = "String for tests.";

        try (final PipedInputStream in = new PipedInputStream();
             final PipedOutputStream outp = new PipedOutputStream(in)) {
            new Thread(() -> {
                try {
                    outp.write(message.getBytes(StandardCharsets.UTF_8));
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }).start();

            System.out.println("result: " + in);
        }
    }

    @Ignore
    @Test
    public void pipedStreams2Test() throws Exception {
        try (final InputStream document = getClass().getResourceAsStream("../doc-1.xml");
             final ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            int next = document.read();
            while (next > -1) {
                bos.write(next);
                next = document.read();
            }
            bos.flush();
            final byte[] result = bos.toByteArray();

            try (final PipedOutputStream poStream = new PipedOutputStream();
                 final PipedInputStream piStream = new PipedInputStream()) {

                // piped input stream connect to the piped output stream
                piStream.connect(poStream);

                // Writes specified byte array.
                poStream.write(result);

                // Reads the next byte of data from this piped input stream.
                for (int i = 0; i < result.length; i++) {
                    System.out.println(piStream.read());
                }
            }
        }
    }

    @Test
    public void digestOutputStreamTest() throws Exception {
        final MessageDigest md = MessageDigest.getInstance("SHA-512");

        try (final OutputStream fos = Files.newOutputStream(Paths.get("/home/claudius/workspace-claudius/expath-crypto/src/org/expath/crypto/tests/string.txt"));
             final DigestOutputStream dos = new DigestOutputStream(fos, md);
             final ObjectOutputStream oos = new ObjectOutputStream(dos)
        ) {

            final String data = "This have I thought good to deliver thee, "
                    + "that thou mightst not lose the dues of rejoicing "
                    + "by being ignorant of what greatness is promised thee.";
            oos.writeObject(data);
            dos.on(false);
            final byte[] digest = md.digest();
            oos.writeObject(digest);
            final int digestLength = digest.length;
            System.out.println("length: " + digestLength);
            final BigInteger bi = new BigInteger(1, digest);
            String result = bi.toString(digestLength);
            if (result.length() % 2 != 0) {
                result = "0" + result;
            }

            System.out.println("result: " + result);
        }
    }

    public InputStream openStream() throws IOException {
        final PipedOutputStream out = new PipedOutputStream();
        final PipedInputStream in = new PipedInputStream(out);

        final Runnable exporter = () -> {
            try {
                out.write("message".getBytes(StandardCharsets.UTF_8));
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            IOUtils.closeQuietly(out);
        };

        // executor.submit(exporter);

        return in;
    }

    @Test
    public void uuid5Test() throws Exception {
        final String seed = "www.widgets.com";

        final NameBasedGenerator uuid_gen_dns = Generators.nameBasedGenerator(NameBasedGenerator.NAMESPACE_DNS);
        final UUID uuid_dns = uuid_gen_dns.generate(seed);
        System.out.println("uuid_dns: " + uuid_dns);

        final NameBasedGenerator uuid_gen_oid = Generators.nameBasedGenerator(NameBasedGenerator.NAMESPACE_OID);
        final UUID uuid_oid = uuid_gen_oid.generate(seed);
        System.out.println("uuid_oid: " + uuid_oid);

        final NameBasedGenerator uuid_gen_url = Generators.nameBasedGenerator(NameBasedGenerator.NAMESPACE_URL);
        final UUID uuid_url = uuid_gen_url.generate(seed);
        System.out.println("uuid_url: " + uuid_url);

        final NameBasedGenerator uuid_gen_x500 = Generators.nameBasedGenerator(NameBasedGenerator.NAMESPACE_X500);
        final UUID uuid_x500 = uuid_gen_x500.generate(seed);
        System.out.println("uuid_x500: " + uuid_x500);
    }

    @Test
    public void uuid5NewTest() throws Exception {
        final String NameSpace_OID_string = "6ba7b812-9dad-11d1-80b4-00c04fd430c8";
        final UUID NameSpace_OID_uuid = UUID.fromString(NameSpace_OID_string);

        final long msb = NameSpace_OID_uuid.getMostSignificantBits();
        final long lsb = NameSpace_OID_uuid.getLeastSignificantBits();

        final byte[] NameSpace_OID_buffer = new byte[16];

        for (int i = 0; i < 8; i++) {
            NameSpace_OID_buffer[i] = (byte) (msb >>> 8 * (7 - i));
        }
        for (int i = 8; i < 16; i++) {
            NameSpace_OID_buffer[i] = (byte) (lsb >>> 8 * (7 - i));
        }

        final String name = "user123";
        final byte[] name_buffer = name.getBytes();


        try (final ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            outputStream.write(NameSpace_OID_buffer);
            outputStream.write(name_buffer);

            final byte byteArray[] = outputStream.toByteArray();
            System.out.println(UUID.nameUUIDFromBytes(byteArray).toString());
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}

