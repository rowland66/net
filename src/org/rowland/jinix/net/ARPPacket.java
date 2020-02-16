package org.rowland.jinix.net;

import java.nio.ByteBuffer;

public class ARPPacket {

    public static short OPERATION_REQUEST = 1;
    public static short OPERATION_REPLY = 2;

    SocketBuffer skb;
    ByteBuffer packetData;

    public ARPPacket(SocketBuffer skb) {
        this.skb = skb;
        this.packetData = skb.getL3Header();
    }

    public ARPPacket() {
        packetData = ByteBuffer.allocate(28);
    }

    public static void setupSKB(SocketBuffer skb) {
        skb.setL4HeaderPosition(0);
        skb.setPayloadPosition(0);
    }

    public ByteBuffer getPacketData() {
        return ((ByteBuffer) packetData.position(0)).slice();
    }

    public short getHardwareType() {
        return packetData.getShort(0);
    }

    public void setHardwareType(int type) {
        packetData.putShort(0, (short) type);
    }

    public short getProtocolType() {
        return packetData.getShort(2);
    }

    public void setProtocolType(int type) {
        packetData.putShort(2, (short) type);
    }

    public int getHardwareAddressLength() {
        return packetData.get(4);
    }

    public void setHardwareAddressLength(int len) {
        packetData.put(4, (byte) len);
    }

    public int getProtocolAddressLength() {
        return packetData.get(5);
    }

    public void setProtocolAddressLength(int len) {
        packetData.put(5, (byte) len);
    }

    public short getOperation() {
        return packetData.getShort(6);
    }

    public void setOperation(short operation) {
        packetData.putShort(6, operation);
    }

    public long getSenderHardwareAddress() {
        byte[] hardareAddressBytes = new byte[8];
        packetData.position(8);
        packetData.get(hardareAddressBytes, 2, 6);
        return ByteBuffer.wrap(hardareAddressBytes).getLong();
    }

    public void setSenderHardwareAddress(long hardwareAddress) {
        byte[] hardareAddressBytes = new byte[8];
        ByteBuffer.wrap(hardareAddressBytes).putLong(hardwareAddress);
        packetData.position(8);
        packetData.put(hardareAddressBytes, 2, 6);
    }

    public int getSenderProtocolAddress() {
        packetData.position(14);
        return packetData.getInt();
    }

    public void setSenderProtocolAddress(int protocolAddress) {
        packetData.position(14);
        packetData.putInt(protocolAddress);
    }

    public long getTargetHardwareAddress() {
        byte[] hardareAddressBytes = new byte[8];
        packetData.position(18);
        packetData.get(hardareAddressBytes, 2, 6);
        return ByteBuffer.wrap(hardareAddressBytes).getLong();
    }

    public void setTargetHardwareAddress(long hardwareAddress) {
        byte[] hardareAddressBytes = new byte[8];
        ByteBuffer.wrap(hardareAddressBytes).putLong(hardwareAddress);
        packetData.position(18);
        packetData.put(hardareAddressBytes, 2, 6);
    }

    public int getTargetProtocolAddress() {
        packetData.position(24);
        return packetData.getInt();
    }

    public void setTargetProtocolAddress(int protocolAddress) {
        packetData.position(24);
        packetData.putInt(protocolAddress);
    }

    private long bytesToLong(byte[] addr) {
        long address  = addr[5] & 0xFFL;
        address |= ((addr[4] << 8) & 0xFF00L);
        address |= ((addr[3] << 16) & 0xFF0000L);
        address |= ((addr[2] << 24) & 0xFF000000L);
        address |= ((addr[1] << 32) & 0xFF00000000L);
        address |= ((addr[0] << 40) & 0xFF0000000000L);
        return address;
    }
}
