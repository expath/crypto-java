/*
 * EXPath Cryptographic Module
 * Java Library providing an EXPath Cryptographic Module
 * Copyright (C) 2015 The EXPath Project
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

import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

public class TestUtils {
    private final static int SIXTEEN_KB = 16 * 1024;
    private final static int FIVE_MB = 5 * 1024 * 1024;

    private static final byte[] SIXTEEN_KB_DATA;
    static {
        SIXTEEN_KB_DATA = new byte[SIXTEEN_KB];  // 16KB buffer
        Arrays.fill(SIXTEEN_KB_DATA, (byte) '1');  // fill with the character '1'
    }

    private static final String FIVE_MB_DATA_STRING;
    static {
        final char[] FIVE_MB_DATA = new char[FIVE_MB];
        Arrays.fill(FIVE_MB_DATA, '1');  // fill with the character '1'
        FIVE_MB_DATA_STRING = new String(FIVE_MB_DATA);
    }

    public static Path generate5MbFile(final File file) throws IOException {
        return generate5MbFile(file.toPath());
    }

    public static Path generate5MbFile(final Path file) throws IOException {
        try (final OutputStream os = Files.newOutputStream(file, StandardOpenOption.TRUNCATE_EXISTING)) {
            final int iterations = FIVE_MB / SIXTEEN_KB;
            for (int i = 0; i < iterations; i++) {
                os.write(SIXTEEN_KB_DATA);
            }
        }
        return file;
    }

    public static String generate5MbString() {
        return FIVE_MB_DATA_STRING;
    }

    public static Document parseXmlString(final String xmlString) throws IOException {
        final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);

        try (final Reader reader = new StringReader(xmlString)) {

            final InputSource is = new InputSource(reader);
            final DocumentBuilder db = documentBuilderFactory.newDocumentBuilder();
            return db.parse(is);

        } catch (final SAXException | ParserConfigurationException e) {
           throw new IOException(e);
        }
    }
}
