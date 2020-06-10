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
package ro.kuberam.libs.java.crypto.utils;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Formatter;

import javax.xml.bind.annotation.adapters.HexBinaryAdapter;

import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import ro.kuberam.tests.junit.BaseTest;

import static junit.framework.TestCase.assertEquals;

public class ByteArray2HexStringPerformanceTest extends BaseTest {

    private static Path tempFile;
    private static byte[] tempByteArray;

    @BeforeClass
    public static void initialize() throws IOException {
        tempFile = generate5MbTempFile().toPath();
        tempByteArray = Files.readAllBytes(tempFile);
    }


    @Test
    public void hexCharsTest() throws Exception {
        final char[] HEX_CHARS = "0123456789abcdef".toCharArray();
        final int tempByteArrayLength = tempByteArray.length;

        final char[] chars = new char[2 * tempByteArrayLength];
        for (int i = 0; i < tempByteArrayLength; ++i) {
            chars[2 * i] = HEX_CHARS[(tempByteArray[i] & 0xF0) >>> 4];
            chars[2 * i + 1] = HEX_CHARS[tempByteArray[i] & 0x0F];
        }
        final String result = new String(chars);
        assertEquals(10400000, result.length());
    }

    @Test
    public void formatterTest() throws Exception {
        final Formatter formatter = new Formatter();
        for (final byte b : tempByteArray) {
            formatter.format("%02x", b);
        }

        final String result = formatter.toString();
        assertEquals(10400000, result.length());
    }

    @Test
    public void stringBuilderTest1() throws Exception {
        final int tempByteArrayLength = tempByteArray.length;

        final StringBuilder strbuf = new StringBuilder(tempByteArrayLength * 2);

        for (int i = 0; i < tempByteArrayLength; i++) {
            if (((int) tempByteArray[i] & 0xff) < 0x10) {
                strbuf.append("0");
            }
            strbuf.append(Long.toString((int) tempByteArray[i] & 0xff, 16));
        }

        final String result = strbuf.toString();
        assertEquals(10400000, result.length());
    }

    @Test
    public void stringBuilderTest2() throws Exception {
        final StringBuilder sb = new StringBuilder();
        for (final byte b : tempByteArray) {
            sb.append(Integer.toHexString((int) (b & 0xff)));
        }

        final String result = sb.toString();
        assertEquals(10400000, result.length());
    }

    @Test
    public void charArrayTest() throws Exception {
        final char[] hexDigits = "0123456789abcdef".toCharArray();
        final char[] byteToHexPair = new char[16 * 16 * 2];
        for (int i = 0, o = 0; i < 256; ++i) {
            byteToHexPair[o++] = hexDigits[i >>> 4];
            byteToHexPair[o++] = hexDigits[i & 15];
        }

        final int tempByteArrayLength = tempByteArray.length;
        final char[] chars = new char[2 * tempByteArrayLength];
        for (int i = 0, o = 0; i < tempByteArrayLength; ++i) {
            int index = tempByteArray[i];
            chars[o++] = byteToHexPair[index++];
            chars[o++] = byteToHexPair[index];
        }

        final String result = new String(chars);
        assertEquals(10400000, result.length());
    }

    @Test
    public void hexArrayTest() throws Exception {
        final int tempByteArrayLength = tempByteArray.length;
        final char[] hexArray = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        final char[] hexChars = new char[tempByteArrayLength * 2];
        int v;
        for (int j = 0; j < tempByteArrayLength; j++) {
            v = tempByteArray[j] & 0xFF;
            hexChars[j * 2] = hexArray[v / 16];
            hexChars[j * 2 + 1] = hexArray[v % 16];
        }

        final String result = new String(hexChars);
        assertEquals(10400000, result.length());
    }

    @Test
    public void stringBuilder1Test() throws Exception {
        final StringBuilder sb = new StringBuilder();
        for (final byte b : tempByteArray) {
            sb.append(String.format("%1$02X", b));
        }

        final String result = sb.toString();
        assertEquals(10400000, result.length());
    }

    @Test
    public void stringBuilder2Test() throws Exception {
        final int tempByteArrayLength = tempByteArray.length;
        final StringBuilder sb = new StringBuilder(tempByteArrayLength * 2);
        for (final byte b : tempByteArray) {
            sb.append(Integer.toHexString(b + 0x800).substring(1));
        }

        final String result = sb.toString();
        assertEquals(10400000, result.length());
    }

    @Test
    public void stringBuilder3Test() throws Exception {
        final int tempByteArrayLength = tempByteArray.length;
        final String digits = "0123456789abcdef";
        final StringBuilder sb = new StringBuilder(tempByteArrayLength * 2);
        for (final byte b : tempByteArray) {
            int bi = b & 0xff;
            sb.append(digits.charAt(bi >> 4));
            sb.append(digits.charAt(bi & 0xf));
        }

        final String result = sb.toString();
        assertEquals(10400000, result.length());
    }

    @Test
    public void stringBuilder4Test() throws Exception {
        final int tempByteArrayLength = tempByteArray.length;
        final StringBuilder hexString = new StringBuilder();
        for (int i = 0; i < tempByteArrayLength; i++) {
            final String hexByte = Integer.toHexString(0xFF & tempByteArray[i]);
            int numDigits = 2 - hexByte.length();
            while (numDigits-- > 0) {
                hexString.append('0');
            }
            hexString.append(hexByte);
        }

        final String result = hexString.toString();
        assertEquals(10400000, result.length());
    }

    @Ignore
    @Test
    public void hexBinaryAdapterTest() throws Exception {
        final String result = new HexBinaryAdapter().marshal(tempByteArray);
        assertEquals(10400000, result.length());
    }

    @Test
    public void integer2Test() throws Exception {
        final int tempByteArrayLength = tempByteArray.length;
        final StringBuilder hexString = new StringBuilder();
        for (int i = 0; i < tempByteArrayLength; i++) {
            final int temp = 0xFF & tempByteArray[i];
            String s = Integer.toHexString(temp);
            if (temp <= 0x0F) {
                s = "0" + s;
            }
            hexString.append(s);
        }

        final String result = hexString.toString();
        assertEquals(10400000, result.length());
    }

    @Test
    @Ignore("too slow, took hours and didn't finish")
    public void integer1Test() throws Exception {
        final int tempByteArrayLengthQuartered = tempByteArray.length / 4;

        String result = "";
        for (int i = 0; i < tempByteArrayLengthQuartered; i++) {
            final int ii = i * 4;
            final int inty = tempByteArray[ii] + tempByteArray[ii + 1] * 0xff + tempByteArray[ii + 2] * 0xffff + tempByteArray[ii + 3] * 0xffffff;
            result = Integer.toHexString(inty) + result;
        }

        assertEquals(10400000, result.length());
    }

    @Test
    @Ignore("too slow")
    public void stringFormatterTest() throws Exception {
        final byte[] a = {0x40, 0x00, 0x39, 0x00};
        final String result = String.format("%0128x", new BigInteger(1, tempByteArray));
    }

}
