package org.rowland.jinix.net;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Created by rsmith on 5/26/2017.
 */
public class EthernetFrame {

    enum EtherType {ARP((short)0x0806),
                   IPV4((short)0x0800);
        private final short headerCode;

        EtherType(short headerCode) {
            this.headerCode = headerCode;
        }

        short getHeaderCode() {
            return headerCode;
        }
    }

    public static long ETHERNET_BROADCAST_ADDR = 0xffffffffffffL;

    private static final int FRAME_OFFSET_DESTINATION_MAC = 0;
    private static final int FRAME_OFFSET_SOURCE_MAC = 6;
    private static final int FRAME_OFFSET_ETHER_TYPE = 12;
    private static final int FRAME_OFFSET_PAYLOAD = 14;

    static final int HEADER_LENGTH = 14;

    private SocketBuffer skb;
    private ByteBuffer data;

    EthernetFrame(SocketBuffer frameData) {
        skb = frameData;
        data = frameData.getL2Header();
    }

    EthernetFrame(byte[] packetData, int size) {
        data = ByteBuffer.wrap(packetData);
        data.order(ByteOrder.BIG_ENDIAN);
        data.limit(size);
    }

    EthernetFrame(long destination, long source, short etherType, SocketBuffer skb) {
        ByteBuffer l2Header;
        if (skb.getL2Header() != null) {
            l2Header = skb.getL2Header();
            l2Header.limit(HEADER_LENGTH + skb.getL3Header().limit());
        } else {
            l2Header = ByteBuffer.allocate(HEADER_LENGTH);
        }
        byte[] macBytes = new byte[8];
        ByteBuffer.wrap(macBytes).putLong(destination);
        l2Header.position(FRAME_OFFSET_DESTINATION_MAC);
        l2Header.put(macBytes, 2, 6);
        ByteBuffer.wrap(macBytes).putLong(source);
        l2Header.position(FRAME_OFFSET_SOURCE_MAC);
        l2Header.put(macBytes, 2, 6);
        l2Header.putShort(FRAME_OFFSET_ETHER_TYPE, etherType);
        l2Header.position(0);
        if (skb.getL2Header() == null) {
            skb.addL2Header(l2Header.array(), HEADER_LENGTH);
        }
    }

    static void setupSKB(SocketBuffer skb) {
        skb.setL3HeaderPosition(HEADER_LENGTH);
    }

    int size() {
        return data.limit();
    }

    long getDestinationHardwareAddress() {
        byte[] mac = new byte[8];
        data.position(FRAME_OFFSET_DESTINATION_MAC);
        data.get(mac, 2, 6);
        return ByteBuffer.wrap(mac).getLong();
    }

    void setDesinationHardwareAddress(long hardwareAddress) {
        byte[] macBytes = new byte[8];
        ByteBuffer.wrap(macBytes).putLong(hardwareAddress);
        data.position(FRAME_OFFSET_DESTINATION_MAC);
        data.put(macBytes, 2, 6);
    }

    long getSourceHardwareAddress() {
        byte[] mac = new byte[8];
        data.position(FRAME_OFFSET_SOURCE_MAC);
        data.get(mac, 2, 6);
        return ByteBuffer.wrap(mac).getLong();
    }

    void setSourceHardwareAddress(long hardwareAddress) {
        byte[] macBytes = new byte[8];
        ByteBuffer.wrap(macBytes).putLong(hardwareAddress);
        data.position(FRAME_OFFSET_SOURCE_MAC);
        data.put(macBytes, 2, 6);
    }

    short getEthernetType() {
        data.position(FRAME_OFFSET_ETHER_TYPE);
        return data.getShort();
    }

    void setEthernetType(int ethernetType) {
        data.position(FRAME_OFFSET_ETHER_TYPE);
        data.putShort((short) ethernetType);
    }

    void releaseSocketBuffer() {
        SocketBuffer.returnSocketBuffer(skb);
        skb = null; // This EthernetFrame should never be used again.
    }

    static String getEthernetMACAsString(long address) {
        byte[] macBytes = new byte[8];
        ByteBuffer bb =ByteBuffer.wrap(macBytes).putLong(address);
        bb.rewind();
        StringBuilder sb = new StringBuilder(30);
        for(int i=0; i<8; i++) {
            if (sb.length() > 0) {
                sb.append("-");
            }
            byte digit = bb.get();
            sb.append(Integer.toHexString(Byte.toUnsignedInt(digit)));
        }
        return sb.toString();
    }

    static String hardwareAddressToString(long hardwareAddress) {
        StringBuffer buffer = new StringBuffer();
        buffer.append(Long.toUnsignedString(((long) (hardwareAddress >> 5*8)) & 0xff, 16)).append("-");
        buffer.append(Long.toUnsignedString(((long) (hardwareAddress >> 4*8)) & 0xff, 16)).append("-");
        buffer.append(Long.toUnsignedString(((long) (hardwareAddress >> 3*8)) & 0xff, 16)).append("-");
        buffer.append(Long.toUnsignedString(((long) (hardwareAddress >> 2*8)) & 0xff, 16)).append("-");
        buffer.append(Long.toUnsignedString(((long) (hardwareAddress >> 8)) & 0xff, 16)).append("-");
        buffer.append(Long.toUnsignedString(((long) hardwareAddress) & 0xff, 16));
        return buffer.toString();
    }

}
