package org.rowland.jinix.net;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.LinkedList;

public class TCPConnection {

    enum State {Closed, Listen, SYN_Sent, SYN_Rcvd, Established, FIN_Wait_1, FIN_Wait_2, Close_Wait, CLosing, Last_Ack, Time_Wait};

    static class TCPConnectionKey {
        int remoteIP;
        int remotePort;
        int localPort;

        TCPConnectionKey(int remoteIP, int remotePort, int localPort) {
            this.remoteIP = remoteIP;
            this.remotePort = remotePort;
            this.localPort = localPort;
        }

        @Override
        public int hashCode() {
            return localPort+remoteIP+remotePort;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj instanceof TCPConnectionKey) {
                return (((TCPConnectionKey) obj).remoteIP == remoteIP &&
                        ((TCPConnectionKey) obj).remotePort == remotePort &&
                        ((TCPConnectionKey) obj).localPort == localPort);
            }
            return false;
        }
    }

    class TransmitPacketHolder {
        int pushTime;
        TCPPacket packet;
    }

    private State state;

    State previousState;

    /**
     * last acknoledged sequence number. beginnign of the unacknowledged
     * sequence numbers
     */
     long sndUnack;

    /** time when the seq number in sndUnack was first acknowledged */
     int sndUnackTime;

    /** next sequence number to send */
     long sndNext;

    /** send window */
     int sndWindow;

    /**
     * sequence number of the incoming segment with whom a window update was
     * done (SND.WL1)
     */
     long sndWndLastUpdateSeq;

    /**
     * acknowledge number of the incoming segment with whom a window update was
     * done (SND.WL2)
     */
     long sndWndLastUpdateAck;

    /** initial sequence number (ISS) */
     long initialSeqNr;

    /** initial remote sequence number (IRS) */
     long initialRemoteSeqNr;

    /** The next sequence number we expect to receive */
     long rcvNext;

    /** recieve window */
     short rcvWindow;

    /** timestamp from the last packet received from the remote side */
     int timeLastRemoteActivity;

    /**
     * maximum segment size which will be set from the remote host in the MSS
     * option or set by the Constant in StackParameters
     */
     int maxSndSegSize;

    /**
     * Send the remaining data and then close the connection
     */
     boolean flushAndClose;

    /**
     * is true if a syn is to send. the sequencenumber of the syn is then stored
     * in synToSendSeq
     *
     */
     boolean synToSend;

    /**
     * sequence number of the syn (needed for retransmitt and acknowledging)
     * this is the sequence number which must be acknowledged so that the syn is
     * acknowledged
     */
     long synToSendSeq;

    /**
     * is true if a fin is to send. The sequencenumber of the fin is then stored
     * in finToSendSeq
     */
     boolean finToSend;

    /**
     * sequence number of the fin (needed for retransmitt and acknowledging)
     * this is the sequence number which must be acknowledged so that the fin is
     * acknowledged
     */
     int finToSendSeq;

    /**
     * in this variable the retransmissions of the same sequence number are counted.
     * if then a acknowledge comes the counter is set to zero
     */
     int numRetransmissions;

    /**
     * indicator that a segment has been received, but not ack'd. If another segment is
     * received before this flag is cleared, send an ack and clear this flag.
     */
    boolean ackDeferred;

    /** time when the last ack was deferred */
    int ackDeferredTime;

     private TCPConnectionKey connectionKey;

     private LinkedList<TCPPacket> receivedPacketList = new LinkedList<>();
     LinkedList<TransmitPacketHolder> transmitPacketList = new LinkedList<>();
     LinkedList<TCPPacket>

     TCPConnectionInputStream iStream;
     TCPConnectionOutputStream oStream;

    TCPConnection() {
        state = State.Closed;
        previousState = null;
    }

    TCPConnection(int localPort) {
        this();
        connectionKey = new TCPConnectionKey(0,0,localPort);
    }

    TCPConnection(int localPort, int remoteIP, int remotePort) {
        this();
        connectionKey = new TCPConnectionKey(remoteIP, remotePort, localPort);
    }

    TCPConnectionKey getConnectionKey() {
        return connectionKey;
    }

    TCPConnectionKey updateListeningConnection(int remoteIP, int remotePort) {
        connectionKey = new TCPConnectionKey(remoteIP, remotePort, connectionKey.localPort);
        return connectionKey;
    }

    TCPConnectionKey updateClosedConnection() {
        connectionKey = new TCPConnectionKey(0, 0, connectionKey.localPort);
        return connectionKey;
    }

    /**
     * Add a received segment to the receivedPacketList. The packets are stored in sequence number order. If the
     * segment added to the list advances the connections rcvNext pointer then the number of bytes advanced (bytesWritten)
     * is returned. If bytesWritten > 0 and one of the segments containing the bytesWritten has its push flag set,
     * any thread blocked reading from the connections OutputStream is notified.
     *
     * @param packet
     * @return
     */
    synchronized long addReceivedSegment(TCPPacket packet) {
        long lowerSeqNmbr = packet.getSeqNr();
        long upperSeqNmbr = lowerSeqNmbr + packet.calculateSegmentLength();

        boolean packetAdded = false;
        if (receivedPacketList.isEmpty()) {
            receivedPacketList.add(packet);
            packetAdded = true;
        } else {
            for (int i = 0; i < receivedPacketList.size(); i++) {
                TCPPacket listPacket = receivedPacketList.get(i);
                if (lowerSeqNmbr <= listPacket.getSeqNr()) {
                    receivedPacketList.add(i, packet);
                    packetAdded = true;
                    break;
                }
            }
        }

        if (!packetAdded) {
            receivedPacketList.addLast(packet);
        }

        long expSeqPay = rcvNext;
        boolean pushFlagSet = false;
        for (TCPPacket listPacket : receivedPacketList) {
            if (rcvNext >= listPacket.getSeqNr()) {
                long offset = rcvNext - listPacket.getSeqNr();
                long segmentLength = listPacket.calculateSegmentLength();
                if (segmentLength > offset) {
                    rcvNext += (segmentLength - offset);
                }
                if (!pushFlagSet && listPacket.isPSHFlagSet()) {
                    pushFlagSet = true;
                }
            } else {
                break;
            }
        }

        long bytesWritten = rcvNext - expSeqPay;

        if (bytesWritten > 0 && pushFlagSet) {
            notifyAll();
        }

        return bytesWritten;
    }

    InputStream getTCPConnectionInputStream() {
        if (iStream == null) {
            iStream = new TCPConnectionInputStream();
        }
        return iStream;
    }

    OutputStream getTCPConnectionOutputStream() {
        if (oStream == null) {
            oStream = new TCPConnectionOutputStream();
        }
        return oStream;
    }

    boolean isOutputStreamClosed() {
        if (oStream != null) {
            return oStream.isClosed();
        }
        return true;
    }

    void abort() {
        try {
            iStream.close();
            oStream.close();
        } catch (IOException e) {
            // Ignore
        }
    }

    void setState(TCPConnection.State state) {
        previousState = this.state;
        this.state = state;
        System.out.println("Entering state: "+state.toString());
    }

    State getState() {
        return this.state;
    }

    public class TCPConnectionInputStream extends InputStream {

        private TCPPacket currentPacket = null;
        int currentPacketOffset;
        long streamPositionSeqNmbr = -1;
        boolean EOF = false;

        private TCPConnectionInputStream() {
            streamPositionSeqNmbr = initialRemoteSeqNr + 1; // Skip the SYN segment that counts as 1
        }

        @Override
        public int read() throws IOException {

            synchronized (TCPConnection.this) {
                while(true) {
                    if (EOF) {
                        return -1;
                    }
                    if (currentPacket == null) {
                        if (!receivedPacketList.isEmpty() && receivedPacketList.getFirst().getSeqNr() == streamPositionSeqNmbr) {
                            currentPacket = receivedPacketList.removeFirst();
                            currentPacketOffset = 0;
                        }
                    }
                    if (currentPacket == null) {
                        try {
                            TCPConnection.this.wait();
                        } catch (InterruptedException e) {
                            return -1;
                        }
                        continue;
                    }

                    int adjustment = 0;
                    if (currentPacket.isFINFlagSet()) {
                        adjustment = 1;
                    }

                    if (currentPacket.calculateSegmentLength() - currentPacketOffset - adjustment > 0) {
                        ByteBuffer bb = currentPacket.getPayloadBuffer();
                        streamPositionSeqNmbr++;
                        return Byte.toUnsignedInt(bb.get(currentPacketOffset++));
                    } else {
                        if (currentPacket.isFINFlagSet()) {
                            EOF = true;
                        }
                        SocketBuffer.returnSocketBuffer(currentPacket.skb);
                        currentPacket = null;
                        currentPacketOffset = 0;
                    }
                }
            }
        }
    }

    public class TCPConnectionOutputStream extends OutputStream
    {
        boolean closed;

        @Override
        public void write(int b) throws IOException {

            if (closed) {
                throw new IOException("Illegal write to closed connection");
            }

            synchronized (TCPConnection.this) {
                if (!transmitPacketList.isEmpty()) {
                    for(TransmitPacketHolder holder : transmitPacketList) {
                        if (holder.packet.getPayloadBuffer().hasRemaining()) {
                            holder.packet.getPayloadBuffer().put((byte) (b & 0xFF));
                            return;
                        }
                    }
                }
                SocketBuffer skb = SocketBuffer.getNextAvailableSocketBuffer();
                TCPPacket packet = new TCPPacket(skb);
                packet.clearHeader(0);
                packet.getPayloadBuffer().put((byte) (b & 0xFF));
                transmitEnqueuePacket(packet);
            }
        }

        @Override
        public void flush() throws IOException {
            synchronized (TCPConnection.this) {
                if (transmitPacketList.isEmpty()) {
                    return;
                }
                TransmitPacketHolder holder = transmitPacketList.getLast();
                TCPPacket packet = holder.packet;
                if (holder.pushTime == 0) {
                    holder.pushTime = (int)(System.currentTimeMillis()&0xFFFFFFFF);
                }
                if (flushAndClose) {
                    packet.setFINFlag();
                }
                packet.setPSHFlag();
            }
        }

        @Override
        public void close() throws IOException {
            super.close();
            flushAndClose = true;
            flush();
            closed = true;
        }

        private void transmitEnqueuePacket(TCPPacket packet) {
            TransmitPacketHolder holder = new TransmitPacketHolder();
            holder.packet = packet;
            transmitPacketList.addLast(holder);
        }

        boolean isNoMoreDataToRead() {
            return (transmitPacketList.isEmpty());
        }

        boolean isClosed() {
            return closed;
        }
    }
}
