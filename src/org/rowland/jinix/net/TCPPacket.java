/*
 * Copyright  (c) 2006-2007 Graz University of Technology. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The names "Graz University of Technology" and "IAIK of Graz University of
 *    Technology" must not be used to endorse or promote products derived from
 *    this software without prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE LICENSOR BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 *  OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 *  OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY  OF SUCH DAMAGE.
 */

package org.rowland.jinix.net;

import java.nio.ByteBuffer;

/**
 * Encapsulating methods to handle a SocketBuffer as a TCP Packet. There are get and set
 * methods for all fields of the TCP header.
 *
 * @author Tobias Kellner
 * @author Ulrich Feichter
 * @author Christof Rath
 * @version $Rev: 939 $ $Date: 2007/09/04 00:56:05 $
 */
public class TCPPacket {

    /** Position of the FIN Flag in the 4th word of the IP header */
    public static final int FIN_MASK = 0x1;

    /** Position of the SYN Flag in the 4th word of the IP header */
    public static final int SYN_MASK = 0x2;

    /** Position of the RST Flag in the 4th word of the IP header */
    public static final int RST_MASK = 0x4;

    /** Position of the PSH Flag in the 4th word of the IP header */
    public static final int PSH_MASK = 0x8;

    /** Position of the ACK Flag in the 4th word of the IP header */
    public static final int ACK_MASK = 0x10;

    /** Position of the URG Flag in the 4th word of the IP header */
    public static final int URG_MASK = 0x20;

    private final static int HEADER_LENGTH = 20;

    private final static int SOURCE_PORT = 0;
    private final static int DESTINATION_PORT = 2;
    private final static int SEQUENCE_NUMBER = 4;
    private final static int ACKNOWLEDGEMENT_NUMBER = 8;
    private final static int DATA_OFFSET = 12;
    private final static int CONTROL_BITS = 13;
    private final static int WINDOW = 14;
    private final static int CHECKSUM = 16;
    private final static int URGENT_POINTER = 18;
    private final static int OPTIONS = 20;

    SocketBuffer skb;

    TCPPacket(SocketBuffer skb) {
        this.skb = skb;
        if (skb.getPayload() == null) {
            skb.setPayload(HEADER_LENGTH);
        }
        if (skb.getL4Header() == null) {
            skb.addL4Header(ByteBuffer.allocate(HEADER_LENGTH).array(), HEADER_LENGTH);
        }
    }

    static void setupSKB(SocketBuffer skb) {
        skb.setPayloadPosition(HEADER_LENGTH);
    }
    /**
     * Get the sending port. The value is read from the TCP header.
     *
     * @return The source port
     */
    int getSourcePort()
    {
        return Short.toUnsignedInt(skb.getL4Header().getShort(SOURCE_PORT));
    }

    /**
     * Set the sending port. The value is set in the TCP header.
     *
     * @param pay
     *            The Payload
     * @param port
     *            The source port
     */
    void setSourcePort(int port)
    {
        skb.getL4Header().putShort(SOURCE_PORT, (short) port);
    }

    /**
     * Get the receiving port. The value is read from the TCP header.
     *
     * @param pay
     *            The Payload
     * @return The destination port
     */
    int getDestPort()
    {
        return Short.toUnsignedInt(skb.getL4Header().getShort(DESTINATION_PORT));
    }

    /**
     * Set the receiving port. The value is set in the TCP header.
     *
     * @param pay
     *            The Payload
     * @param port
     *            The destination port
     */
    void setDestPort(int port)
    {
        skb.getL4Header().putShort(DESTINATION_PORT, (short) port);
    }

    /**
     * Get the Sequence number. If the SYN flag is present then this is the
     * initial sequence number and the first data byte is the sequence number
     * plus 1. Otherwise if the SYN flag is not present then the first data byte
     * is the sequence number. The value is read from the TCP header.
     *
     * @param pay
     *            The Payload
     * @return The Sequence number
     */
    long getSeqNr()
    {
        return Integer.toUnsignedLong(skb.getL4Header().getInt(SEQUENCE_NUMBER));
    }

    /**
     * Set the Sequence number. If the SYN flag is present then this is the
     * initial sequence number and the first data byte is the sequence number
     * plus 1. Otherwise if the SYN flag is not present then the first data byte
     * is the sequence number. The value is set in the TCP header.
     *
     * @param pay
     *            The Payload
     * @param seqNr
     *            The Sequence number
     */
    void setSeqNr(long seqNr)
    {
        skb.getL4Header().putInt(SEQUENCE_NUMBER, (int) seqNr);
    }

    /**
     * Get the Acknowledgement number. If the ACK flag is set then the value of
     * this field is the sequence number the sender expects next. The value is
     * read from the TCP header.
     *
     * @param pay
     *            The Payload
     * @return The Acknowledgement number
     */
    long getAckNr()
    {
        return Integer.toUnsignedLong(skb.getL4Header().getInt(ACKNOWLEDGEMENT_NUMBER));
    }

    /**
     * Set the Acknowledgement number. If the ACK flag is set then the value of
     * this field is the sequence number the sender expects next. The value is
     * set in the TCP header.
     *
     * @param pay
     *            The Payload
     * @param ackNr
     *            The Acknowledgement number
     */
    void setAckNr(long ackNr)
    {
        skb.getL4Header().putInt(ACKNOWLEDGEMENT_NUMBER, (int) ackNr);
    }

    /**
     * Get the Data offset. This is the size of the TCP header in 32-bit words.
     * (min. 5, max. 15) The value is read from the TCP header.
     *
     * @param pay
     *            The Payload
     * @return The Data offset
     */
    int getDataOffset()
    {
        return (skb.getL4Header().get(DATA_OFFSET) >>> 4) & 0x0f;
    }

    /**
     * Set the Data offset. This is the size of the TCP header in 32-bit words.
     * (min. 5, max. 15) The value is set in the TCP header.
     *
     * @param pay
     *            The Payload
     * @param ofs
     *            The Data offset
     */
    void setDataOffset(int ofs)
    {
        skb.getL4Header().put(DATA_OFFSET, (byte) ((ofs & 0xF) << 4));
    }

    // TODO: Reserved field

    /**
     * Check whether the FIN Flag is set. No more data from sender. The value is
     * read from the TCP header.
     *
     * @return Whether the FIN Flag is set
     */
    boolean isFINFlagSet()
    {
        return (skb.getL4Header().get(CONTROL_BITS) & FIN_MASK) != 0;
    }

    /**
     * Set the FIN Flag. No more data from sender. The value is set in the TCP
     * header.
     *
     * @param pay
     *            The Payload
     */
    void setFINFlag()
    {
        skb.getL4Header().put(CONTROL_BITS, (byte) (skb.L4Header.get(CONTROL_BITS) | FIN_MASK));
    }

    /**
     * Clear the FIN Flag. No more data from sender. The value is set in the TCP
     * header.*
     */
    void clearFINFlag()
    {
        skb.getL4Header().put(CONTROL_BITS, (byte) (skb.L4Header.get(CONTROL_BITS) & ~FIN_MASK));
    }

    /**
     * Check whether the SYN Flag is set. Synchronize sequence numbers. The
     * value is read from the TCP header.
     *
     * @return Whether the SYN Flag is set
     */
    boolean isSYNFlagSet()
    {
        return (skb.getL4Header().get(CONTROL_BITS) & SYN_MASK) != 0;
    }

    /**
     * Set the SYN Flag. Synchronize sequence numbers. The value is set in the
     * TCP header.
     *
     * @param pay
     *            The Payload
     */
    void setSYNFlag()
    {
        skb.getL4Header().put(CONTROL_BITS, (byte) (skb.L4Header.get(CONTROL_BITS) | SYN_MASK));
    }

    /**
     * Clear the SYN Flag. Synchronize sequence numbers. The value is set in the
     * TCP header.
     *
     * @param pay
     *            The Payload
     */
    void clearSYNFlag()
    {
        skb.getL4Header().put(CONTROL_BITS, (byte) (skb.L4Header.get(CONTROL_BITS) & ~SYN_MASK));
    }

    /**
     * Check whether the RST Flag is set. Reset the connection. The value is
     * read from the TCP header.
     *
     * @return Whether the RST Flag is set
     */
    boolean isRSTFlagSet()
    {
        return (skb.getL4Header().get(CONTROL_BITS) & RST_MASK) != 0;
    }

    /**
     * Set the RST Flag. Reset the connection. The value is set in the TCP
     * header.
     *
     * @param pay
     *            The Payload
     */
    void setRSTFlag()
    {
        skb.getL4Header().put(CONTROL_BITS, (byte) (skb.L4Header.get(CONTROL_BITS) | RST_MASK));
    }

    /**
     * Clear the RST Flag. Reset the connection. The value is set in the TCP
     * header.
     */
    void clearRSTFlag()
    {
        skb.getL4Header().put(CONTROL_BITS, (byte) (skb.L4Header.get(CONTROL_BITS) & ~RST_MASK));
    }

    /**
     * Check whether the PSH Flag is set. Push function. The value is read from
     * the TCP header.
     *
     * @return Whether the PSH Flag is set
     */
    boolean isPSHFlagSet()
    {
        return (skb.getL4Header().get(CONTROL_BITS) & PSH_MASK) != 0;
    }

    /**
     * Set the PSH Flag. Push function. The value is set in the TCP header.
     *
     * @param pay
     *            The Payload
     */
    void setPSHFlag()
    {
        skb.getL4Header().put(CONTROL_BITS, (byte) (skb.L4Header.get(CONTROL_BITS) | PSH_MASK));
    }

    /**
     * Clear the PSH Flag. Push function. The value is set in the TCP header.
     *
     * @param pay
     *            The Payload
     */
    void clearPSHFlag()
    {
        skb.getL4Header().put(CONTROL_BITS, (byte) (skb.L4Header.get(CONTROL_BITS) & ~PSH_MASK));
    }

    /**
     * Check whether the ACK Flag is set. Acknowledgement field is significant.
     * The value is read from the TCP header.
     *
     * @return Whether the ACK Flag is set
     */
    boolean isACKFlagSet()
    {
        return (skb.getL4Header().get(CONTROL_BITS) & ACK_MASK) != 0;
    }

    /**
     * Set the ACK Flag. Acknowledgement field is significant. The value is set
     * in the TCP header.
     *
     * @param pay
     *            The Payload
     */
    void setACKFlag()
    {
        skb.getL4Header().put(CONTROL_BITS, (byte) (skb.getL4Header().get(CONTROL_BITS) | ACK_MASK));
    }

    /**
     * Clear the ACK Flag. Acknowledgement field is significant. The value is
     * set in the TCP header.*
     */
     void clearACKFlag()
    {
        skb.getL4Header().put(CONTROL_BITS, (byte) (skb.getL4Header().get(CONTROL_BITS) & ~ACK_MASK));
    }

    /**
     * Check whether the URG Flag is set. Urgent pointer field is significant.
     * The value is read from the TCP header.
     *
     * @return Whether the Flag is set
     */
    boolean isURGFlagSet()
    {
        return (skb.getL4Header().get(CONTROL_BITS) & URG_MASK) != 0;
    }

    /**
     * Set the URG Flag. Urgent pointer field is significant. The value is set
     * in the TCP header.
     *
     * @param pay
     *            The Payload
     */
    void setURGFlag()
    {
        skb.getL4Header().put(CONTROL_BITS, (byte) (skb.getL4Header().get(CONTROL_BITS) | URG_MASK));
    }

    /**
     * Clear the URG Flag. Urgent pointer field is significant. The value is set
     * in the TCP header.
     *
     * @param pay
     *            The Payload
     */
    void clearURGFlag()
    {
        skb.getL4Header().put(CONTROL_BITS, (byte) (skb.getL4Header().get(CONTROL_BITS) & ~URG_MASK));
    }

    /**
     * Get the Window size. The number of bytes the sender is willing to receive
     * starting from the acknowledgement field value. The value is read from the
     * TCP header.
     *
     * @return The Window
     */
    int getWindow()
    {
        return Short.toUnsignedInt(skb.getL4Header().getShort(WINDOW));
    }

    /**
     * Set the Window size. The number of bytes the sender is willing to receive
     * starting from the acknowledgement field value. The value is set in the
     * TCP header.
     *
     * @param pay
     *            The Payload
     * @param wnd
     *            The Window
     */
    void setWindow(int wnd)
    {
        skb.getL4Header().putShort(WINDOW, (short) wnd);
    }

    /**
     * Get the Header Checksum. The checksum is calculated over the TCP header
     * (+IP Pseudoheader) and the data. The value is read from the TCP header.
     *
     * @return The Header Checksum
     */
    int getChecksum()
    {
        return Short.toUnsignedInt(skb.getL4Header().getShort(CHECKSUM));
    }

    /**
     * Set the Header Checksum to the correct value. The checksum is calculated
     * over the TCP header (+IP Pseudoheader) and the data. (with the checksum
     * field set to zero). The calculation is done in
     * {@link TCPPacket#calculateChecksum(Payload)}. The value is set in the
     * TCP header.
     *
     */
    void setChecksum(int senderAddress, int destinationAddress)
    {
        skb.getL4Header().putShort(CHECKSUM, (short) 0);
        skb.getL4Header().putShort(CHECKSUM, (short) calculateChecksum(senderAddress, destinationAddress));
    }

    /**
     * Get the Urgent pointer. An offset from the sequence number indicating the
     * last urgent data byte. The value is read from the TCP header.
     *
     * @return The Urgent pointer
     */
    int getURGPointer()
    {
        return Short.toUnsignedInt(skb.getL4Header().getShort(URGENT_POINTER));
    }

    /**
     * Set the Urgent pointer. An offset from the sequence number indicating the
     * last urgent data byte. The value is set in the TCP header.
     *
     * @param pay
     *            The Payload
     * @param urgP
     *            The Urgent pointer
     */
    void setURGPointer(int urgP)
    {
        skb.getL4Header().putShort(URGENT_POINTER, (short) urgP);
    }

    public byte[] getOptions() {
        byte[] rtrn = new byte[getDataOffset()*4-OPTIONS];
        ByteBuffer header = skb.getL4Header();
        header.position(OPTIONS);
        header.get(rtrn);
        return rtrn;
    }

    /**
     * Calculate the correct Checksum. The checksum is calculated over the TCP
     * header (+IP Pseudoheader) and the data (with the checksum field assumed
     * to be zero).
     *
     * @return The Checksum
     */
    private int calculateChecksum(int senderAddress, int destinationAddress)
    {
        ByteBuffer TCPData = (ByteBuffer) skb.getL4Header().position(0);

        int sum = 0;
        int packetShorts = ((int) TCPData.limit() / 2) * 2;
        while ((TCPData.position()) < packetShorts) {
            sum += (int) (TCPData.getShort() & 0xffff); // Required because Java lacks an unsigned short;
        }

        if (TCPData.position() < TCPData.limit()) {
            sum += (TCPData.get() << 8) & 0xff00;
        }

        // compute over the pseudo header
        if (senderAddress == 0 && destinationAddress == 0) {
            IP4Packet ip4Packet = new IP4Packet(skb);
            sum += (ip4Packet.getDestinationAddress() & 0xFFFF) + (ip4Packet.getDestinationAddress() >>> 16);
            sum += (ip4Packet.getSourceAddress() & 0xFFFF) + (ip4Packet.getSourceAddress() >>> 16);
            sum += ip4Packet.getProtocol() & 0x00FF;
            sum += TCPData.limit() & 0xFFFF;
        } else {
            sum += (destinationAddress & 0xFFFF) + (destinationAddress >>> 16);
            sum += (senderAddress & 0xFFFF) + (senderAddress >>> 16);
            sum += ProtocolHandler.Protocol.TCP.ipHeaderCode & 0x00FF;
            sum += TCPData.limit() & 0xFFFF;
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        return (short) ~sum;
    }

    /**
     * Check whether the checksum is valid.
     *
     * @return Whether the checksum is valid.
     */
    boolean hasValidChecksum()
    {
        return calculateChecksum(0, 0) == 0;
    }

    /**
     * Appends the option header to set the Maximum Segmentation Size (MSS)
     * according to the maximum size of payload buffer.
     * <p>
     * <b>Note:</b> This option has to be transmitted only during the initial
     * connection request! The TCP payload data already written to the Payload
     * pay will be overwritten! => do it before storing data
     *
     * @param pay
     *            The Payload
     */
    void setMMS()
    {
        int dofs = getDataOffset();

        // and change the data offset
        setDataOffset((byte) (dofs + 1));
        skb.getL4Header().limit(skb.getL4Header().limit()+4);

        // add the option header (first byte = 2: MSS option, second byte = 4:
        // number
        // of bytes for this option, the other two bytes for the actual size)
        skb.getL4Header().putInt(skb.getL4Header().limit()-4, 0x02040000 | (StackParameters.TCP_RCV_MAX_SEGMENT_SIZE & 0xFFFF));
    }

    /**
     * Returns the length of the payload in octets. This is the size of the IP
     * packet minus the size of the IP and the TCP headers.
     *
     * @param pay
     *            The Payload
     * @return The number of payload octets
     */
    int getDataLength()
    {
        return skb.getL4Header().limit() - (getDataOffset() * 4);
    }

    /**
     * Create an empty TCP segment from a given {@link Payload}. All header
     * bits are set to 0, except the data offset which will be set correctly.
     * Option length is assumed to be 0.
     *
     * @param pay
     *            The Payload
     */
    void emptyPayload()
    {
        emptyPayload(0);
    }

    /**
     * Create an empty TCP segment from a given {@link Payload}. All header
     * bits are set to 0, except the data offset which will be set correctly.
     * NOTE: Not used at the moment (only by {@link #emptyPayload(Payload)}.
     *
     * @param optionLength
     *            Length of the option data (in units of 4 bytes)
     */
    void emptyPayload(int optionLength)
    {
        // set whole tcp header to 0
        ByteBuffer header = skb.getL4Header();
        header.limit((5 + optionLength) *4);
        clearHeader(0);
    }

    /**
     * Clear the TCP header bytes and set the data offset based on the option length
     *
     * @param optionLength
     */
    void clearHeader(int optionLength) {
        ByteBuffer header = skb.getL4Header();
        header.position(0);
        for (int i = 0; i < 5 + optionLength; i++) {
            header.putInt(0);
        }
        setDataOffset(5 + optionLength);
    }

    /**
     * Calculates the segment length of a given Payload, counting also the Syn
     * or Fin flag
     *
     * @param pay
     *            the given Payload
     * @return positive integer with the length in octets
     */
    int calculateSegmentLength()
    {
        int length = getDataLength();
        if (isFINFlagSet())
            length++;
        if (isSYNFlagSet())
            length++;
        return length;
    }

    ByteBuffer getPayloadBuffer() {
        return skb.getPayload();
    }

    /**
     * Close the payload buffer for any further writes. This method must be called before sending the packet.
     */
    void closePayloadBuffer() {
        skb.getPayload().flip();
        skb.getL4Header().limit(getDataOffset()*4+skb.getPayload().limit());

    }
}
