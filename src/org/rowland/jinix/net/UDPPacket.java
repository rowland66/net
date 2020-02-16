package org.rowland.jinix.net;

import sun.nio.ch.DirectBuffer;

import java.nio.ByteBuffer;

public class UDPPacket {

    private final static int HEADER_LENGTH = 8;

    private final static int SOURCE_PORT = 0;
    private final static int DESTINATION_PORT = 2;
    private final static int PACKET_LENGTH = 4;
    private final static int CHECKSUM = 6;


    SocketBuffer skb;
    ByteBuffer payload;

    UDPPacket(SocketBuffer skb) {
        this.skb = skb;
        payload = ((ByteBuffer) skb.getL4Header().position(HEADER_LENGTH)).slice();
    }

    UDPPacket(int sourcePort, int destPort, SocketBuffer skb) {
        this.skb = skb;

        ByteBuffer packetData;
        if (skb.getL4Header() != null) {
            packetData = skb.getL4Header();
        } else {
            packetData = ByteBuffer.allocate(HEADER_LENGTH);
        }
        packetData.putShort(SOURCE_PORT, (short) sourcePort);
        packetData.putShort(DESTINATION_PORT, (short) destPort);
        packetData.putShort(PACKET_LENGTH, (short) (HEADER_LENGTH + payload.limit()));
        packetData.putShort(CHECKSUM, (short) 0);
        packetData.putShort(CHECKSUM, calcCheckSum());
        packetData.position(0);
        if (skb.getL4Header() == null) {
            skb.addL4Header(packetData.array(), HEADER_LENGTH);
        }
    }


    int getSourcePort() {
        return skb.getL4Header().getShort(SOURCE_PORT);
    }

    int getDestinationPort() {
        return skb.getL4Header().getShort(DESTINATION_PORT);
    }

    int getLength() {
        return skb.getL4Header().getShort(PACKET_LENGTH);
    }

    int getCheckSum() {
        return skb.getL4Header().getShort(CHECKSUM);
    }

    byte[] getPayload() {
        byte[] rtrn = new byte[payload.limit()];
        payload.rewind();
        payload.get(rtrn);
        return rtrn;
    }

    boolean isValid() {
        return getLength() == skb.getL4Header().limit();
    }

    boolean hasValidCheckSum() {
        return (calcCheckSum() == 0);
    }

    private short calcCheckSum() {
        ByteBuffer UDPData = (ByteBuffer) skb.getL4Header().position(0);

        int sum = 0;
        int packetShorts = ((int) getLength() / 2) * 2;
        while ((UDPData.position()) < packetShorts) {
            sum += (int) (UDPData.getShort() & 0xffff); // Required because Java lacks an unsigned short;
        }

        if (UDPData.position() < UDPData.limit()) {
            sum += (UDPData.get() << 8) & 0xff00;
        }

        // compute over the pseudo header
        IP4Packet ip4Packet = new IP4Packet(skb);
        sum += (ip4Packet.getDestinationAddress() & 0xFFFF) + (ip4Packet.getDestinationAddress() >>> 16);
        sum += (ip4Packet.getSourceAddress() & 0xFFFF) + (ip4Packet.getSourceAddress() >>> 16);
        sum += ip4Packet.getProtocol() & 0x00FF;
        sum += getLength() & 0xFFFF;

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        return (short) ~sum;
    }

}
