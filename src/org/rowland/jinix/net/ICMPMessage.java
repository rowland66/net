package org.rowland.jinix.net;

import java.nio.ByteBuffer;

public class ICMPMessage {

    static final byte TYPE_ECHO = 8;
    static final byte TYPE_ECHO_REPLY = 0;

    private static final int HEADER_LENGTH = 8;

    SocketBuffer skb;
    ByteBuffer ICMPMessage;

    ICMPMessage(SocketBuffer skb) {
        this.skb = skb;
        ICMPMessage = skb.getL4Header();
    }

    ICMPMessage(SocketBuffer skb, ByteBuffer payload) {
        this.skb = skb;
        this.skb.setPayload(payload, HEADER_LENGTH);
        this.skb.addL4Header(new byte[HEADER_LENGTH], HEADER_LENGTH);
        ICMPMessage = skb.getL4Header();
    }

    public static void setupSKB(SocketBuffer skb) {
        skb.setPayloadPosition(HEADER_LENGTH);
    }

    byte getType() {
        return ICMPMessage.get(0);
    }

    void setType(int type) {
        ICMPMessage.put(0, (byte) type);
    }

    byte getCode() { return ICMPMessage.get(1); }

    void setCode(int code) {
        ICMPMessage.put(1, (byte) code);
    }

    short getCheckSum() {
        return ICMPMessage.getShort(2);
    }

    void setCheckSum() {
        ICMPMessage.putShort(2, (short) 0);
        short checkSum = calcCheckSum();
        ICMPMessage.putShort(2, checkSum);
    }

    boolean hasValidCheckSum() {
        short checkSum = calcCheckSum();
        return (checkSum == 0);
    }

    void setIdentifier(int identifier) {
        ICMPMessage.putShort(4, (short) identifier);
    }

    void setSequenceNumber(int sequenceNumber) {
        ICMPMessage.putShort(6, (short) sequenceNumber);
    }

    private short calcCheckSum() {
        ICMPMessage.position(0);

        int sum = 0;
        while ((ICMPMessage.position()) < ICMPMessage.limit()) {
            sum += (int) (ICMPMessage.getShort() & 0xffff); // Required because Java lacks an unsigned short;
        }

        if (ICMPMessage.position() < ICMPMessage.limit()) {
            sum += (ICMPMessage.get() << 8) & 0xff00;
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        return (short) ~sum;
    }
}
