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
package ro.kuberam.libs.java.crypto.digest;

import java.io.InputStream;
import java.nio.file.Files;

import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertTrue;

public class HmacLargeBinaryWithSha1 extends BaseTest {

    @Test
    public void hmacLargeBinaryWithSha1() throws Exception {
        final String input = new String(Files.readAllBytes(generate5MbTempFile().toPath()), UTF_8);
        final String secretKey = "/hWLmb8xRM75bOS6fyV9Pn0mf3Aiw+HphRCL8nOq";
        final String result = Hmac.hmac(input.getBytes(UTF_8),
                secretKey.getBytes(UTF_8), "HMAC-SHA-1", "base64");

        System.out.println(result);

        assertTrue(result.equals("McKrpaWMrn0fzAlfw0yVDxy9esE="));
    }

    @Test
    public void hmacLargeBinaryWithSha1_inputStream() throws Exception {
        try(final InputStream is = Files.newInputStream(generate5MbTempFile().toPath())) {
            final String secretKey = "/hWLmb8xRM75bOS6fyV9Pn0mf3Aiw+HphRCL8nOq";
            final String result = Hmac.hmac(is,
                    secretKey.getBytes(UTF_8), "HMAC-SHA-1", "base64");

            System.out.println(result);

            assertTrue(result.equals("McKrpaWMrn0fzAlfw0yVDxy9esE="));
        }
    }
}
