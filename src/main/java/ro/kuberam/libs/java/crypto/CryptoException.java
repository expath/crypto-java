/*
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

import javax.annotation.Nullable;

public class CryptoException extends Exception {
	private static final long serialVersionUID = -2606956271206243301L;
	@Nullable private final CryptoError cryptoError;

	public CryptoException(final CryptoError cryptoError) {
		super(cryptoError.getDescription());
		this.cryptoError = cryptoError;
	}

	public CryptoException(final CryptoError cryptoError, final Throwable cause) {
		super(cryptoError.getDescription(), cause);
		this.cryptoError = cryptoError;
	}
	
	public CryptoException(final Throwable cause) {
		super(getDesc(cause), cause);
		this.cryptoError = CryptoError.describeException(cause);
	}

	private static String getDesc(final Throwable cause) {
		final CryptoError cryptoError = CryptoError.describeException(cause);
		if (cryptoError != null) {
			return cryptoError.getDescription();
		} else {
			return cause.getMessage();
		}
	}

	@Nullable
	public CryptoError getCryptoError() {
		return cryptoError;
	}
}
