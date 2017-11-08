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

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

public class PipedIOApp {
    public static void main(final String args[]) {
        final Thread thread1 = new Thread(new PipeOutput("Producer"));
        final Thread thread2 = new Thread(new PipeInput("Consumer"));
        thread1.start();
        thread2.start();
        boolean thread1IsAlive = true;
        boolean thread2IsAlive = true;
        do {
            if (thread1IsAlive && !thread1.isAlive()) {
                thread1IsAlive = false;
            }
            if (thread2IsAlive && !thread2.isAlive()) {
                thread2IsAlive = false;
            }
        } while (thread1IsAlive || thread2IsAlive);
    }
}

class PipeIO {
    static final PipedOutputStream outputPipe = new PipedOutputStream();

    static final PipedInputStream inputPipe = new PipedInputStream();

    static {
        try {
            outputPipe.connect(inputPipe);
        } catch (final IOException ex) {
            System.out.println("IOException in static initializer");
        }
    }

    String name;

    public PipeIO(final String id) {
        name = id;
    }
}

class PipeOutput extends PipeIO implements Runnable {
    public PipeOutput(final String id) {
        super(id);
    }

    @Override
    public void run() {
        final String s = "This is a test.";
        try {
            for (int i = 0; i < s.length(); ++i) {
                outputPipe.write(s.charAt(i));
                System.out.println(name + " wrote " + s.charAt(i));
            }
            outputPipe.write('!');
        } catch (final IOException ex) {
            System.out.println("IOException in PipeOutput");
        }
    }
}

class PipeInput extends PipeIO implements Runnable {
    public PipeInput(final String id) {
        super(id);
    }

    @Override
    public void run() {
        boolean eof = false;
        try {
            while (!eof) {
                final int inChar = inputPipe.read();
                if (inChar != -1) {
                    char ch = (char) inChar;
                    if (ch == '!') {
                        eof = true;
                        break;
                    } else {
                        System.out.println(name + " read " + ch);
                    }
                }
            }
        } catch (final IOException ex) {
            System.out.println("IOException in PipeOutput");
        }
    }
}
