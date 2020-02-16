package org.rowland.jinix.net;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

public class ByteBufferInputStream extends InputStream {

    ByteBuffer bb;

    ByteBufferInputStream(ByteBuffer byteBuffer) {
        bb = byteBuffer;
    }

    @Override
    public int read() throws IOException {
        synchronized(bb) {
            bb.flip();

            try {
                if (bb.hasRemaining()) {
                    return Byte.toUnsignedInt(bb.get());
                } else {
                    bb.compact();
                    try {
                        bb.wait();
                    } catch (InterruptedException e) {
                        return -1;
                    }
                    return read();
                }
            } finally {
                bb.compact();
            }
        }
    }

    public int write(byte b) {
        synchronized (bb) {
            if (bb.hasRemaining()) {
                bb.put(b);
                bb.notifyAll();
                return 1;
            } else {
                return 0;
            }
        }
    }
}
