package ro.kuberam.libs.java.crypto.junit;

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
    private DataInputStream in;
   
    public ReceiverThread(InputStream is) {
        in = new DataInputStream(is);
    }
   
    @Override
    public void run() {
        //Reading data from the stream
         try
       {
             System.out.println(in.readDouble() + " " + in.readChar() + " " + in.readInt());
         }
         catch (Exception e) {
             e.printStackTrace();
       }
    }
}

/*
 * Producer thread class - sends bytes data to the stream
 */
class SenderThread extends Thread {
    private DataOutputStream out;
   
    public SenderThread(OutputStream os) {
        out = new DataOutputStream(os);
    }
   
    @Override
    public void run() {
        //Writing data to the stream
         try
       {
             out.writeDouble(123.45);
             out.writeChar('c');
             out.writeInt(67);
         }
         catch (Exception e) {
             e.printStackTrace();
       }
    }
   
}

public class PipedInputStreamExample {
       
    public static void main(String[] args) throws Exception {
        PipedOutputStream pos = new PipedOutputStream();
        PipedInputStream pis = new PipedInputStream(pos);
        SenderThread senderThread = new SenderThread(pos);
        ReceiverThread receiverThread = new ReceiverThread(pis);
        senderThread.start();  //send data to the piped stream
        receiverThread.start();//read data from the same piped stream
       
        //wait for all threads to finish
        senderThread.join();
        receiverThread.join();
        pis.close();
        pos.close();
    }
}
