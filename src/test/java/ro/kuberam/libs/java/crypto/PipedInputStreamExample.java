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

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

/**
 * Java PipedInputStream example
 * shows how to read bytes in one Java thread
 * sent by PipedOutputStream object from another Java thread
 */

/*
 * Receiver thread class - reads bytes from the stream
 */
class ReceiverThread extends Thread {
    private final DataInputStream in;

    public ReceiverThread(final InputStream is) {
        in = new DataInputStream(is);
    }

    @Override
    public void run() {
        //Reading data from the stream
        try {
            System.out.println(in.readDouble() + " " + in.readChar() + " " + in.readInt());
        } catch (final Exception e) {
            e.printStackTrace();
        }
    }
}

/*
 * Producer thread class - sends bytes data to the stream
 */
class SenderThread extends Thread {
    private final DataOutputStream out;

    public SenderThread(final OutputStream os) {
        out = new DataOutputStream(os);
    }

    @Override
    public void run() {
        //Writing data to the stream
        try {
            out.writeDouble(123.45);
            out.writeChar('c');
            out.writeInt(67);
        } catch (final Exception e) {
            e.printStackTrace();
        }
    }

}

public class PipedInputStreamExample {

    public static void main(final String[] args) throws Exception {
        try (final PipedOutputStream pos = new PipedOutputStream();
             final PipedInputStream pis = new PipedInputStream(pos)) {

            final SenderThread senderThread = new SenderThread(pos);
            final ReceiverThread receiverThread = new ReceiverThread(pis);
            senderThread.start();  //send data to the piped stream
            receiverThread.start();//read data from the same piped stream

            //wait for all threads to finish
            senderThread.join();
            receiverThread.join();
        }
    }
}
