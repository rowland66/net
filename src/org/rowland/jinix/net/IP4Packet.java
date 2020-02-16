package org.rowland.jinix.net;

import java.nio.ByteBuffer;

/**
 * Created by rsmith on 5/30/2017.
 */
public class IP4Packet {

    private static final int VERSION = 0;
    private static final int TYPE_OF_SERVICE = 1;
    private static final int TOTAL_LENGTH = 2;
    private static final int IDENTIFICATION = 4;
    private static final int FRAGMENTATION = 6;
    private static final int TIME_TO_LIVE = 8;
    private static final int PROTOCOL = 9;
    private static final int CHECKSUM = 10;
    private static final int SOURCE_ADDRESS = 12;
    private static final int DESTINATION_ADDRESS = 16;
    private static final int OPTIONS = 20;

    static final int HEADER_LENGTH = 20;

    private SocketBuffer skb;
    private ByteBuffer packetData;

    /**
     * Create an IP4Packet from a SocketBuffer that has been received over the wire.
     *
     * @param skb
     */
    IP4Packet(SocketBuffer skb) {
        this.skb = skb;
        if (skb.getL3Header() != null) {
            packetData = skb.getL3Header();
            packetData.limit(HEADER_LENGTH + skb.getL4Header().limit());
        } else {
            packetData = ByteBuffer.allocate(HEADER_LENGTH);
            skb.addL3Header(packetData.array(), HEADER_LENGTH);
        }
    }

    /**
     * Create an IP4Packet from a SocketBuffer that only contains a payload. The SocketBuffer may have been received and
     * is being updated to be sent out, or it may be a new SocketBuffer that is being prepared to sent out.
     *
     * @param protocol
     * @param fragmentID
     * @param source
     * @param destination
     * @param skb
     */
    IP4Packet(byte protocol, short fragmentID, int source, int destination, SocketBuffer skb) {
        this.skb = skb;

        if (skb.getL3Header() != null) {
            packetData = skb.getL3Header();
            packetData.limit(HEADER_LENGTH + skb.getL4Header().limit());
        } else {
            packetData = ByteBuffer.allocate(HEADER_LENGTH);
        }
        packetData.put(VERSION, (byte) (((4 << 4) & 0xf0) + 5)); // Version: 4 IHL: 5
        packetData.putShort(TOTAL_LENGTH, (short) (HEADER_LENGTH + skb.getL4Header().limit())); // As short is signed, it is not adequate for large packets
        packetData.putShort(IDENTIFICATION, fragmentID);
        packetData.putShort(FRAGMENTATION, (short) 0x4000);
        packetData.put(TIME_TO_LIVE, (byte) 64);
        packetData.put(PROTOCOL, (byte) protocol);
        packetData.putInt(SOURCE_ADDRESS, source);
        packetData.putInt(DESTINATION_ADDRESS, destination);
        setCheckSum();
        packetData.position(0);
        if (skb.getL3Header() == null) {
            skb.addL3Header(packetData.array(), HEADER_LENGTH);
        }
    }

    static void setupSKB(SocketBuffer skb) {
        skb.setL4HeaderPosition(HEADER_LENGTH);
    }

    ByteBuffer getPacketData() {
        return ((ByteBuffer) packetData.position(0)).slice();
    }

    int getVersion() {
        return (packetData.get(VERSION) & 0xf0) >>> 4;
    }

    int getHeaderLength() {
        return (packetData.get(VERSION) & 0x0f) * 4;
    }

    int getTotalLength() {
        return packetData.getShort(TOTAL_LENGTH);
    }

    int getFragmentID() {
        return packetData.getShort(IDENTIFICATION);
    }

    boolean isDoNotFragment() {
        return ((packetData.get(FRAGMENTATION) & 0x40) > 0 ? true : false);
    }

    boolean isMoreFragments() {
        return ((packetData.get(FRAGMENTATION) & 0x20) > 0 ? true : false);
    }

    int getFragmentOffset() {
        return packetData.getShort(FRAGMENTATION) & 0x1fff;
    }

    int getTimeToLive() {
        return packetData.get(TIME_TO_LIVE);
    }

    int getProtocol() {
        return packetData.get(PROTOCOL);
    }

    short getCheckSum() {
        return packetData.getShort(CHECKSUM);
    }

    int getSourceAddress() {
        return packetData.getInt(SOURCE_ADDRESS);
    }

    int getDestinationAddress() {
        return packetData.getInt(DESTINATION_ADDRESS);
    }

    private void setCheckSum() {
        packetData.putShort(CHECKSUM, (short)0);
        packetData.putShort(CHECKSUM, calcCheckSum());
    }

    boolean hasValidCheckSum() {
        return (calcCheckSum() == 0);
    }

    private short calcCheckSum() {
        packetData.position(0);
        int headerLength = getHeaderLength();

        int sum = 0;

        while (packetData.position() < headerLength) {
            sum += (int) (packetData.getShort() & 0xffff);
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        return (short) ~sum;
    }
}
