package ro.kuberam.libs.java.crypto.junit;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

public class PipedIOApp {
	public static void main(String args[]) {
		Thread thread1 = new Thread(new PipeOutput("Producer"));
		Thread thread2 = new Thread(new PipeInput("Consumer"));
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
	static PipedOutputStream outputPipe = new PipedOutputStream();

	static PipedInputStream inputPipe = new PipedInputStream();
	static {
		try {
			outputPipe.connect(inputPipe);
		} catch (IOException ex) {
			System.out.println("IOException in static initializer");
		}
	}

	String name;

	public PipeIO(String id) {
		name = id;
	}
}

class PipeOutput extends PipeIO implements Runnable {
	public PipeOutput(String id) {
		super(id);
	}

	public void run() {
		String s = "This is a test.";
		try {
			for (int i = 0; i < s.length(); ++i) {
				outputPipe.write(s.charAt(i));
				System.out.println(name + " wrote " + s.charAt(i));
			}
			outputPipe.write('!');
		} catch (IOException ex) {
			System.out.println("IOException in PipeOutput");
		}
	}
}

class PipeInput extends PipeIO implements Runnable {
	public PipeInput(String id) {
		super(id);
	}

	public void run() {
		boolean eof = false;
		try {
			while (!eof) {
				int inChar = inputPipe.read();
				if (inChar != -1) {
					char ch = (char) inChar;
					if (ch == '!') {
						eof = true;
						break;
					} else
						System.out.println(name + " read " + ch);
				}
			}
		} catch (IOException ex) {
			System.out.println("IOException in PipeOutput");
		}
	}
}
