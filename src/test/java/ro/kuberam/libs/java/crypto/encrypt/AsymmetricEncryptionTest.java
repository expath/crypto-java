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
package ro.kuberam.libs.java.crypto.encrypt;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.io.IOUtils;
import org.junit.Ignore;
import org.junit.Test;

import ro.kuberam.libs.java.crypto.CryptoModuleTests;

public class AsymmetricEncryptionTest extends CryptoModuleTests {

	@Test
	public void encryptStringWithAesSymmetricKey() throws Exception {
		try (InputStream is = getClass().getResourceAsStream("../rsa-private-key.key")) {
			String privateKey = IOUtils.toString(is, UTF_8);
			System.out.println("privateKey = " + privateKey);

			String result = AsymmetricEncryption.encryptString(longInput, privateKey,
					"RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

			System.out.println(result);
		}
	}

	@Ignore
	@Test
	public void testFilesList() throws IOException {
		Path directory = Paths.get("/home/claudius/backup");
		String prefix = "full-backup";
		String suffix = "4.4.0";
		int zipFilesMax = 12;

//		Arrays.asList(1, 2, 3, 4, 5).stream().forEach(i -> {
//			try {
//				Files.createDirectory(directory.resolve("full-backup-2018010" + i + "-4.4.0"));
//			} catch (IOException e) {
//				e.printStackTrace();
//			}
//		});

		Predicate<Path> filter = path -> {
			String entryName = path.getFileName().toString();

			return entryName.startsWith(prefix) && entryName.endsWith(suffix);
		};

		List<Path> entriesPaths = list(directory, filter);
		int entriesNumber = entriesPaths.size();
		int numberOfEntriesToBeDeleted = entriesNumber - zipFilesMax + 1;

		Comparator<Path> timestampComparator = new Comparator<Path>() {
			public int compare(Path o1, Path o2) {
				int result = 0;

				try {
					result = Files.getLastModifiedTime(o1).compareTo(Files.getLastModifiedTime(o2));
				} catch (IOException e) {
					e.printStackTrace();
				}

				return result;
			}
		};

		if (numberOfEntriesToBeDeleted > 0) {
			entriesPaths.stream().sorted(timestampComparator).limit(numberOfEntriesToBeDeleted).forEach(path -> {
				System.out.println(path);
//				try {
//					Files.delete(path);
//				} catch (IOException e) {
//					e.printStackTrace();
//				}
			});
		}

	}

	private List<Path> list(Path directory, Predicate<Path> filter) throws IOException {
		try (final Stream<Path> entries = Files.list(directory).filter(filter)) {
			return entries.collect(Collectors.toList());
		}
	}

}
