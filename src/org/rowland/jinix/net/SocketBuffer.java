package org.rowland.jinix.net;

import sun.nio.ch.DirectBuffer;

import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.List;

public class SocketBuffer {

    private static final int BUFFER_SIZE = 1600;
    private static final int MAX_IP4_PAYLOAD_SIZE = 1500 - IP4Packet.HEADER_LENGTH;

    private static List<SocketBuffer> freeList = new LinkedList<>();

    public enum Direction {RECEIVE, SEND};

    ByteBuffer data;
    ByteBuffer payload;
    ByteBuffer L4Header; // ICMP, UDP, TCP, ...
    ByteBuffer L3Header; // IP
    ByteBuffer L2Header; // Ethernet

    private int useCount;

    public static synchronized SocketBuffer getNextAvailableSocketBuffer() {
        SocketBuffer rtrnValue = null;
        if (freeList.isEmpty()) {
            rtrnValue = new SocketBuffer();
            //System.out.println("Allocating skb: "+rtrnValue.toString());
        } else {
            rtrnValue = freeList.remove(0);
            //System.out.println("Removing skb from pool: "+rtrnValue.toString());
        }
        rtrnValue.useCount++;
        return rtrnValue;
    }

    public static synchronized void returnSocketBuffer(SocketBuffer skb) {
        skb.useCount--;
        if (skb.useCount == 0) {
            skb.clear();
            freeList.add(skb);
            //System.out.println("Returning skb to pool: "+skb.toString());
        }
    }

    /**
     * Private constructor. Use getNextAvailableSocketBuffer() method to obtain a socket buffer for use.
     */
    private SocketBuffer() {
        data = ByteBuffer.allocateDirect(BUFFER_SIZE);
    }

    /**
     * Private constructor used by factory methods that create an SKB from and SKB.
     * @param data
     * @param l2
     * @param l3
     * @param l4
     * @param payload
     * @param useCount
     */
    private SocketBuffer(ByteBuffer data, ByteBuffer l2, ByteBuffer l3, ByteBuffer l4, ByteBuffer payload, int useCount) {
        this.data = data;
        this.L2Header = l2;
        this.L3Header = l3;
        this.L4Header = l4;
        this.payload = payload;
        this.useCount = useCount;
    }

    /**
     * Increment the use count of a SocketBuffer. The use count only needs to be incremented when the socket is reused.
     * SocketBuffers obtained with getNextAvailableSocketBuffer() already have use count set to 1.
     */
    public void incrementUseCount() {
        useCount++;
    }

    /**
     * Set the position of the payload relative to the L4Header.
     *
     * @param payloadPosition position of the payload relative to the L4Header
     */
    public void setPayloadPosition(int payloadPosition) {
        L4Header.position(payloadPosition);
        payload = L4Header.slice();
    }

    /**
     * Set the payload in a new SocketBuffer. This method is used when a SocketBuffer to transmit. This method will
     * store the payload in the buffer leaving room for the various headers that will need to be added before it.
     *
     * @param payload
     * @param l4HeaderLength the length in bytes of the L4Header. Used to allocate room before the payload in the buffer
     */
    public void setPayload(ByteBuffer payload, int l4HeaderLength) {

        if (payload.limit() > MAX_IP4_PAYLOAD_SIZE - l4HeaderLength) {
            throw new RuntimeException("SocketBuffer payload to large");
        }
        data.position(EthernetFrame.HEADER_LENGTH + IP4Packet.HEADER_LENGTH + l4HeaderLength);
        data.put(payload);
        data.limit(data.position());
        data.position(EthernetFrame.HEADER_LENGTH + IP4Packet.HEADER_LENGTH + l4HeaderLength);
        this.payload = data.slice();
    }

    void setPayload(int l4HeaderLength) {
        data.position(EthernetFrame.HEADER_LENGTH + IP4Packet.HEADER_LENGTH + l4HeaderLength);
        this.payload = data.slice();
    }

    public ByteBuffer getDataBuffer() {
        return data;
    }

    /**
     * Initialize the SocketBuffer after a new L2 frame has been copied into it. This method is used for frames receeived
     * over the wire.
     *
     * @param framesize the size of the frame. Provided by whatever process copied the frame data into the buffer
     */
    public void initializeL2(int framesize) {
        data.limit(framesize);
        data.position(0);
        L2Header = data.slice();
    }

    /**
     * Add an L2Header (ie. Ethernet) to the existing buffer content. The L2Header bytes are added before the first
     * existing header in the buffer or the payload itself.
     *
     * @param l2Header L2Header bytes
     */
    public void addL2Header(byte[] l2Header, int headerLength) {
        if (this.payload == null) {
            throw new IllegalStateException("Payload has not been set.");
        }

        long payloadStart;
        if (this.L3Header != null) {
            payloadStart = ((DirectBuffer) this.L3Header).address() - ((DirectBuffer) data).address();
        } else if (this.L4Header != null) {
            payloadStart = ((DirectBuffer) this.L4Header).address() - ((DirectBuffer) data).address();
        } else {
            payloadStart = ((DirectBuffer) this.payload).address() - ((DirectBuffer) data).address();
        }

        long l2HeaderStart = payloadStart - l2Header.length;
        this.data.position((int)l2HeaderStart);
        this.L2Header = data.slice();
        this.L2Header.put(l2Header, 0 , headerLength);
    }

    public ByteBuffer getL2Header() {
        return L2Header;
    }

    public void setL3HeaderPosition(int l3HeaderPosition) {
        L2Header.position(l3HeaderPosition);
        L3Header = L2Header.slice();
    }

    public void addL3Header(byte[] l3Header, int headerLength) {
        if (this.payload == null) {
            throw new IllegalStateException("Payload has not been set.");
        }

        long payloadStart;
        if (this.L4Header != null) {
            payloadStart = ((DirectBuffer) this.L4Header).address() - ((DirectBuffer) data).address();
        } else {
            payloadStart = ((DirectBuffer) this.payload).address() - ((DirectBuffer) data).address();
        }

        long l3HeaderStart = payloadStart - l3Header.length;
        this.data.position((int)l3HeaderStart);
        this.L3Header = data.slice();
        this.L3Header.put(l3Header, 0, headerLength);
    }

    public ByteBuffer getL3Header() {
        return L3Header;
    }

    public void setL4HeaderPosition(int l4HeaderPosition) {
        L3Header.position(l4HeaderPosition);
        L4Header = L3Header.slice();
    }

    public ByteBuffer getL4Header() {
        return L4Header;
    }

    public void addL4Header(byte[] l4Header, int headerLength) {
        long payloadStart = ((DirectBuffer) this.payload).address() - ((DirectBuffer) data).address();
        long l4HeaderStart = payloadStart - l4Header.length;
        this.data.position((int)l4HeaderStart);
        this.L4Header = data.slice();
        this.L4Header.put(l4Header, 0, headerLength);
    }

    public ByteBuffer getPayload() {
        return payload;
    }

    private void clear() {
        data.position(0);
        data.limit(data.capacity());
        payload = null;
        L4Header = null;
        L3Header = null;
        L2Header = null;
    }
}
