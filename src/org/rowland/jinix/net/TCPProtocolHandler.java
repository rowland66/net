package org.rowland.jinix.net;

import org.rowland.jinix.net.util.NumFunctions;

import java.util.HashMap;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

public class TCPProtocolHandler implements ProtocolHandler {

    InternetProtocolHandler ipHandler;
    Map<TCPConnection.TCPConnectionKey, TCPConnection> connectionMap = new HashMap();
    Timer packetSendTimer = new Timer("Send Packet", true);

    /** Initial window size */
    static short initialWindow = StackParameters.TCP_INITIAL_WINDOW_SIZE;

    private void updateListeningConnection(TCPConnection conn, int sourceAddress, int sourcePort) {
        connectionMap.remove(conn.getConnectionKey());
        conn.updateListeningConnection(sourceAddress, sourcePort);
        connectionMap.put(conn.getConnectionKey(), conn);
    }

    private void updateClosedConnection(TCPConnection conn) {
        connectionMap.remove(conn.getConnectionKey());
        conn.updateClosedConnection();
        connectionMap.put(conn.getConnectionKey(), conn);
    }

    TCPProtocolHandler(InternetProtocolHandler ipHandler) {
        this.ipHandler = ipHandler;
        NumFunctions.init();
        packetSendTimer.schedule(new SendPackets(), 50L, 50L);
    }

    @Override
    public void processMessage(SocketBuffer skb) {
        TCPPacket.setupSKB(skb);
        TCPPacket packet = new TCPPacket(skb);
        IP4Packet ipPacket = new IP4Packet(skb);
        if (!packet.hasValidChecksum()) {
            System.out.println("Bad checksum on TCP packet");
            return;
        }

        TCPConnection.TCPConnectionKey lookupKey =
                new TCPConnection.TCPConnectionKey(ipPacket.getSourceAddress(), packet.getSourcePort(), packet.getDestPort());
        TCPConnection conn = connectionMap.get(lookupKey);
        if (conn == null) {
            lookupKey = new TCPConnection.TCPConnectionKey(0, 0, packet.getDestPort());
            conn = connectionMap.get(lookupKey);
            if (conn == null) {
                System.out.println("Packet recieved for unknown connection");
                if (!packet.isRSTFlagSet())
                    sendBackReset(skb);
                return;
            }
        }

        synchronized (conn) {
            conn.timeLastRemoteActivity = (int) (System.currentTimeMillis() & 0xFFFFFFFF);
            switch (conn.getState()) {
                case Listen:
                    establishConnectionPassive1(conn, skb);
                    break;

                case SYN_Sent:
                    //establishConnectionActive(conn, skb);
                    break;

                case SYN_Rcvd:
                    establishConnectionPassive2(conn, skb);
                    break;

                case Established:
                    handleEstablishedState(conn, skb);
                    break;

                case FIN_Wait_1:
                    closeConnectionActive1(conn, skb);
                    break;

                case FIN_Wait_2:
                    //closeConnectionActive2(conn, skb);
                    break;

                case Close_Wait:
                    closeConnectionPassive1(conn, skb);
                    break;

                case CLosing:
                    //closeConnectionActive3(conn, skb);
                    break;

                case Last_Ack:
                    closeConnectionPassive2(conn, skb);
                    break;

                case Time_Wait:
                    //closeConnectionActive4(conn, skb);
                    break;

                default:
            }
        }
    }

    TCPConnection listen(int port) {
        TCPConnection conn = new TCPConnection(port);
        conn.setState(TCPConnection.State.Listen);
        connectionMap.put(conn.getConnectionKey(), conn);
        synchronized (conn) {
            try {
                conn.wait();
            } catch (InterruptedException e) {
                return null;
            }
            return conn;
        }
    }

    //*************************** FIRST SOME COMMON METHODS **********************
    /**
     * Get an initial randomly generated sequence number.
     *
     * @return the new initial sequence number
     */
    synchronized private static long getSeqStart()
    {
        return Integer.toUnsignedLong(NumFunctions.rand.nextInt());
    }

    /**
     * Searches for the MSS option in the tcp header. If MSS is set correctly
     * the value will be stored in <code>conn.maxSndSegSize</code>
     *
     * @param conn
     * 			<code>TCPConnection</code> to which the Segment was adressed
     * @param pay
     * 			<code>Payload</code> to check
     */
    private static void checkAndHandleMSS(TCPConnection conn, TCPPacket packet)
    {
        if (packet.getDataOffset() <= 5)
            return;
        int mss = -1;
        int i = 0;

        byte[] options = packet.getOptions();
        while (i < options.length)
        {
            byte processedByte = options[i];
            switch (processedByte)
            {
                case 0x00: // End of option list
                    return;
                case 0x01: // NOP
                    i++;
                    continue;
                case 0x02: // MSS
                    if (options[i+1]  == 0x04)
                    {
                        mss = 0;
                        mss = (Byte.toUnsignedInt(options[i+2]) << 8) + Byte.toUnsignedInt(options[i+3]);
                        break;
                    }
                    else
                        return; // error in tcp header
                default: // read out the length of the other options and
                    // increment i
                    //i += (pay.payload[(i + 1) / 4] >>> ((3 - (i + 1) % 4) * 8)) & 0xFF;
                    continue;
            }
            break;
        }
        if (mss != -1)
        {
            conn.maxSndSegSize = mss;
        }
    }

    /**
     * Takes the given segment form a reset response and sends it.
     *
     * @param pay
     * 			The <code>Payload</code> containing the segment.
     */
    private void sendBackReset(SocketBuffer skb)
    {
        System.out.println("sending reset");
        TCPPacket packet = new TCPPacket(skb);
        IP4Packet ipPacket = new IP4Packet(skb);

        int srcPort = packet.getSourcePort();
        int dstPort = packet.getDestPort();
        int srcAddr = ipPacket.getSourceAddress();
        if (packet.isACKFlagSet())
        {
            long rcvAck = packet.getAckNr();
            packet.emptyPayload();
            packet.setSeqNr(rcvAck);
        }
        else
        {
            long rcvSeq = packet.getSeqNr();
            int rcvLength = packet.calculateSegmentLength();
            packet.emptyPayload();
            packet.setAckNr(rcvSeq + rcvLength);
            packet.setACKFlag();
        }
        packet.setRSTFlag();
        packet.setDestPort(srcPort);
        packet.setSourcePort(dstPort);
        packet.setChecksum(0, 0);

        skb.incrementUseCount();
        ipHandler.sendIPMessage(ipPacket.getSourceAddress(), Protocol.TCP, skb);
    }

    /**
     * Checks if a segment pay is acceptable checking the sequence number.
     * It returns true if a part of the recieved segment is in the reciever
     * window, else it returns false. (see RFC 793 pg.69)
     *
     * @param conn
     *            the connection from which the bounds shall be taken
     * @param pay
     *            <code>Payload</code> containing the segmen
     *
     * @return true if accptable, else false
     */
    private boolean isSeqAcceptable(TCPConnection conn, SocketBuffer skb)
    {
        TCPPacket packet = new TCPPacket(skb);
        IP4Packet ipPacket = new IP4Packet(skb);

        if (!isSegmentInReceiverWindow(conn, packet.getSeqNr(), packet.calculateSegmentLength())) {
            System.out.println("ERROR: Segment not in window ");
				System.out.println("Values: rcvNext: " + Long.toHexString(conn.rcvNext) + " seqNr: "
					+ Long.toHexString(packet.getSeqNr()) + " segment length: "
					+ packet.calculateSegmentLength() + " window: " + (int) (conn.rcvWindow & 0xFFFF));
            // sending a ack so that reciever knows wich numbers we are using
            if (packet.isRSTFlagSet()) {
                return false;
            }
            packet.emptyPayload();
            skb.incrementUseCount();
            sendEmptyPacket(conn, skb, conn.getConnectionKey().remoteIP);
            // ack
            return false;
        }
        return true;
    }

    /**
     * Checks if a payload contains a certain seqNr.
     *
     * @param seqNr
     *            the sequence number to look for
     * @param pay
     *            the Payload to check
     * @return whether the Payload contains the seqNr
     */
    public boolean isSeqNrInPayload(long seqNr, SocketBuffer skb) {

        TCPPacket packet = new TCPPacket(skb);

        return NumFunctions.isBetweenOrEqualSmaller(packet.getSeqNr(),
                packet.getSeqNr() + packet.calculateSegmentLength(),
                seqNr);
    }

    /**
     * Used to check if even a part of a given Segment lies in the reciever
     * window space.
     *
     * @param conn
     *            The <code>TCPConnection</code> wich should process this Segment
     * @param seqNr
     *            The sequence number of the segment wich should be checked
     * @param segLength
     *            The segment length including the FIN or SYN flag
     * @return true if the segment lies in the window, else false
     */
    private static boolean isSegmentInReceiverWindow(TCPConnection conn, long seqNr, int segLength)
    {
        //assert segLength >= 0; // should not be longer than short

        if (conn.rcvWindow == 0)
            if (segLength > 0)
                return false;
            else
                return (seqNr == conn.rcvNext);
        else if (segLength == 0)
            return isSeqNrInWindow(conn, seqNr);
        else
            return isSeqNrInWindow(conn, seqNr) || isSeqNrInWindow(conn, seqNr + segLength - 1);
    }

    /**
     * Checks if a given sequence number seqNr lies in the reciever window set
     * in the passed <code>TCPConnection</code> conn.
     * Used by isPacketInRecieveSpace()
     *
     * @param conn
     *            the TCPConnection
     * @param seqNr
     * 	          the sequence number to check
     * @return true if seqNr lies in the window, else false
     */
    private static boolean isSeqNrInWindow(TCPConnection conn, long seqNr)
    {
        int window = conn.rcvWindow & 0xFFFF; // window must be positive
        return NumFunctions.isBetweenOrEqualSmaller(conn.rcvNext, conn.rcvNext + window, seqNr);
    }

    /**
     * Checks if a given acknowledge number ackNr lies in the sender window set
     * in the passed <code>TCPConnection</code> conn.
     *
     * @param conn
     *            the TCPConnection
     * @param ackNr
     *            acknowledge number to check
     * @return true if ackNr lies in the window, else false
     */
    private boolean isAckNrInWindow(TCPConnection conn, int ackNr)
    {
        return NumFunctions.isBetweenOrEqualBigger((int) conn.sndUnack, (int) conn.sndNext, ackNr);
    }

    /**
     * Handles the acknowledge flag and number for the established state.
     * It may also be used in FIN WAIT 1, FIN_WAIT_2, CLOSE and CLOSE_WAIT.
     * Window updates by the remote side are also handled here.
     *
     * @param conn
     * 			the connection
     * @param pay
     * 			the payload
     * @return true if no error occured (and packet can be further processed)
     */
    private boolean handleAck(TCPConnection conn, SocketBuffer skb)
    {
        TCPPacket packet = new TCPPacket(skb);
        IP4Packet ipPacket = new IP4Packet(skb);

        // Hendl-Eck :)
        if (!packet.isACKFlagSet())
        {
            System.out.println("ERROR: ACK not set, dropping");
            return false;
        }
        if (conn.sndUnack == packet.getAckNr())
        {
            System.out.println("acked another time");
            conn.sndUnackTime = (int) (System.currentTimeMillis() & 0xFFFFFFFF);
            handleSenderWindow(conn, skb);
        }
        else if (isAckNrInWindow(conn, (int) packet.getAckNr())) // is ack awaited?
        {
            // check if send window can be updated (RFC793 pg.72)
            long oldSndUnack = conn.sndUnack;
            conn.sndUnack = packet.getAckNr();
            conn.sndUnackTime = (int) (System.currentTimeMillis() & 0xFFFFFFFF);
            conn.numRetransmissions = 0; // if we were in a retransmission, now it was acked
            long difference = NumFunctions.calcDiffWithOverflow((int) conn.sndUnack, (int) oldSndUnack);
            //	assert difference > 0; // unack time whould be wrong if equal 0
            System.out.println("Some data was acked");

            // check if a syn or a fin were sent before to dont ack this
            // sequence numbers in the oStream
            if (conn.synToSend)
                if (NumFunctions.isBetweenOrEqualBigger((int) oldSndUnack, (int) conn.sndUnack, (int) conn.synToSendSeq))
                {
                    difference--;
                    conn.synToSend = false;
                }
            if (conn.finToSend)
                if (NumFunctions.isBetweenOrEqualBigger((int) oldSndUnack, (int) conn.sndUnack, conn.finToSendSeq))
                {
                    difference--;
                    conn.finToSend = false;
                }
            //conn.oStream.ackData(difference);
            handleSenderWindow(conn, skb);
            return true;
        }
        else if (NumFunctions.isBetween((int) conn.sndUnack, (int) conn.sndNext, (int) packet.getAckNr())
                // ACK Nr between unack + next -> error
                || (NumFunctions.calcDiffWithOverflow(conn.sndUnack, packet
                .getAckNr()) > NumFunctions.calcDiffWithOverflow(packet.getAckNr(),
                conn.sndNext)) // ACK Nr closer to next -> error
                )
        // TCPPacket.getAckNr(pay) > sndUnack
        {
            System.out.println("ERROR: Unexpected Ack");
            packet.emptyPayload();

            skb.incrementUseCount();
            ipHandler.sendIPMessage(ipPacket.getSourceAddress(), Protocol.TCP, skb);

            return false;
        }

        return true;
    }

    /**
     * Is used in {@link #handleAck(TCPConnection, Payload)} (Hendl-Eck :) to update
     * the window information sent by the remote host.
     * @param conn
     * 			The connection
     * @param pay
     * 			The segment
     */
    private void handleSenderWindow(TCPConnection conn, SocketBuffer skb)
    {
        TCPPacket packet = new TCPPacket(skb);
        IP4Packet ipPacket = new IP4Packet(skb);

        // check if segment is valid for window update (see RFC)
        if (conn.sndWndLastUpdateSeq < packet.getSeqNr() ||
                (conn.sndWndLastUpdateSeq == packet.getSeqNr() ||
                        conn.sndWndLastUpdateAck <= packet.getAckNr()))
        {
            conn.sndWindow = packet.getWindow();
            // if now sndNext is bigger than sndUnack + snd.Window set it
            // smaller
            if (NumFunctions.isBetweenOrEqualSmaller(conn.sndUnack, conn.sndNext, conn.sndUnack
                    + (conn.sndWindow & 0xFFFF)))
            {
                System.out.println("remote window was reduced, starting retransmission");
                // simply start retransmission, easier do handle :)
                // TODO: set sndNext = sndUnack + conn.sndWindow and the pointer in iStream to the
                // right values
                conn.sndNext = packet.getAckNr();
                //if(!conn.oStream.isBufferEmpty())
                //    conn.oStream.setPtrForRetransmit();
            }
        }
    }

    /**
     * Sends a TCP Packet by handing it to the lower (network) layer.
     * Just calls <code>sendEmptyPacket(conn, pay, true)</code>
     *
     * @see #sendEmptyPacket(TCPConnection, Payload, boolean)
     *
     * @param conn
     *            The corresponding TCP Connection
     * @param pay
     *            The payload of the Packet
     */
    private void sendEmptyPacket(TCPConnection conn, SocketBuffer skb, int destinationAddress)
    {
        sendEmptyPacket(conn, skb, destinationAddress, true);
    }

    /**
     * Sends a TCP Packet by handing it to the lower (network) layer.
     * No data will be added by this method, but data which is already
     * in the <code>Payload</code> will not be touched.
     * It also sets the sequence number field to <code>conn.sndNext</code>
     * and if not otherwise requested also the acknowledge flag will be
     * set and the acknowledge number will get the value from
     * <code>conn.rcvNext</code>.
     *
     * @param conn
     *            The corresponding TCP Connection
     * @param skb
     *            The payload of the Packet
     * @param sendAck
     *            If set, the Ack flag will be set and the acknowledge number
     *            will be set correctly.
     */
    private void sendEmptyPacket(TCPConnection conn, SocketBuffer skb, int destinationAddress, boolean sendAck)
    {
        TCPPacket packet = new TCPPacket(skb);

        packet.setWindow(conn.rcvWindow);
        packet.setSourcePort(conn.getConnectionKey().localPort);
        packet.setDestPort(conn.getConnectionKey().remotePort);
        packet.setSeqNr(conn.sndNext);
        conn.sndNext += packet.calculateSegmentLength();
        if (sendAck)
            packet.setACKFlag();
        packet.setAckNr(conn.rcvNext);
        packet.setChecksum(ipHandler.protocolAddress, destinationAddress);
        ipHandler.sendIPMessage(conn.getConnectionKey().remoteIP, Protocol.TCP, skb);
    }

    /**
     * Reads out the data stored in a <code>Payload</code> and stores it in the connection's
     * <code>TCPinputStream</code>.
     *
     * @param conn
     *            the <code>TCPConnection</code> containing the stream
     * @param pay
     *            the Payload
     * @param offset
     *            the offset at which to start reading within the payload
     * @return how many bytes were read out including SYN and FIN flags!!
     */
    /*
    private static int readOutPayloadData(TCPConnection conn, SocketBuffer skb, int offset)
    {
        TCPPacket packet = new TCPPacket(skb);

        int bytesWritten = 0;
        if (packet.getDataLength() > 0)
        {
            ByteBuffer dataBuffer = packet.getPayloadBuffer();
            dataBuffer.position(offset);
            while (dataBuffer.hasRemaining()) {
                int b = conn.iStream.write(dataBuffer.get());
                if (b == 0) {
                    break;
                }
                bytesWritten++;
            }
        }
            if (bytesWritten == packet.getDataLength())
                System.out.println("All data was read out from packet");

        //assert bytesWritten <= TCPPacket.getDataLength(pay);

        // count fin after all data in the packet was acked
        if (bytesWritten == packet.getDataLength() && packet.isFINFlagSet())
        {
            bytesWritten++;
        }
        // syn is counted before data is recieved
        if (packet.isSYNFlagSet() && offset == 0)
        {
            bytesWritten++;
        }

        System.out.println("Stored bytes");
        return bytesWritten;
    } */

    /**
     * Process a valid FIN flag for all states.
     *
     * @param conn the connection
     * @return whether sendAck has to be set
     */
    private static boolean processFIN(TCPConnection conn)
    {
        boolean setSendFIN = false;

        // Signal user "connection closing"
        switch (conn.getState())
        {
            case SYN_Rcvd:
                // fall through
            case Established:
                conn.setState(TCPConnection.State.Close_Wait);
                // Only send FIN if the output stream was never opened, or has been closed and all data sent.
                if (conn.isOutputStreamClosed() && conn.transmitPacketList.isEmpty())
                {
                    setSendFIN = true;
                    conn.setState(TCPConnection.State.Last_Ack);
                }
                break;

            case FIN_Wait_1:
                if (conn.sndNext == conn.sndUnack && conn.oStream.isNoMoreDataToRead()) // FIN ACKed
                { // never reached
                    conn.setState(TCPConnection.State.Time_Wait);
                }
                else
                {
                    conn.setState(TCPConnection.State.CLosing);
                }
                break;

            case FIN_Wait_2:
                conn.setState(TCPConnection.State.Time_Wait);
                break;
        }
        return setSendFIN;
    }

    private class SendPackets extends TimerTask {

        @Override
        public void run() {
            int currentTime = (int)(System.currentTimeMillis()&0xFFFFFFFF);
            for (TCPConnection connection : connectionMap.values()) {
                synchronized (connection) {
                    boolean sendAck = false;
                    // If the connection has an ack that has been deferred by more than the deferred ack timeout,
                    // send an ack segment.
                    if (connection.ackDeferred && (currentTime - connection.ackDeferredTime) > 250) {
                        connection.ackDeferred = false;
                        sendAck = true;
                    }

                    TCPPacket packet = null;
                    if (!connection.transmitPacketList.isEmpty()) {
                        TCPConnection.TransmitPacketHolder holder = connection.transmitPacketList.getFirst();
                        if (sendAck || (currentTime - holder.pushTime) > 250 || !holder.packet.getPayloadBuffer().hasRemaining()) {
                            holder = connection.transmitPacketList.remove();
                            packet = holder.packet;
                            packet.closePayloadBuffer();
                        }
                    } else {
                        if (sendAck) {
                            SocketBuffer skb = SocketBuffer.getNextAvailableSocketBuffer();
                            packet = new TCPPacket(skb);
                            packet.emptyPayload();
                        }
                    }

                    if (packet != null) {
                        System.out.println("Sending deferred " + packet.getDataLength() + " bytes with ack " + sendAck + " and FIN " + packet.isFINFlagSet());

                        if (packet.isFINFlagSet() && connection.getState() == TCPConnection.State.Close_Wait) {
                            connection.setState(TCPConnection.State.Last_Ack);
                        }
                        // We should only be sending an ack if there is not data to send. Otherwise, sending thread should deliver acks
                        sendEmptyPacket(connection, packet.skb, connection.getConnectionKey().remoteIP, sendAck);
                    } else {
                        //System.out.println("Sending no packets");
                    }
                }
            }
        }
    }

     //	------------------------------ the receive methods -----------------------------
    /**
     * Method which is invoked when a segment arrives in state LISTEN. It looks
     * for a Packet with the SYN flag set, and if such a Packet arrives a
     * SYN-ACK is sent back and the state is switched then to SYN_RECIEVED. The
     * behaviour on other setted flags is implementet according RFC 793
     *
     * @param conn
     *            <code>TCPConnection</code> for who the packet was sent
     * @param pay
     *            <code>Payload</code> which contains the segment
     */
    private void establishConnectionPassive1(TCPConnection conn, SocketBuffer skb)
    {
        TCPPacket packet = new TCPPacket(skb);
        IP4Packet ipPacket = new IP4Packet(skb);

        // STATE_LISTEN
        if (packet.isRSTFlagSet())
        {
            return;
        }
        if (packet.isACKFlagSet())
        {
            sendBackReset(skb);
            return;
        }
        if (!packet.isSYNFlagSet())
        {
            return;
        }

        conn.initialSeqNr = getSeqStart();
        if (conn.initialSeqNr < 0) {
            throw new RuntimeException("seqStart < 0");
        }

        // TODO: check priority security and so on... not so important (see RFC)
        updateListeningConnection(conn, ipPacket.getSourceAddress(), packet.getSourcePort());
        conn.rcvNext = packet.getSeqNr() + 1;
        conn.initialRemoteSeqNr = packet.getSeqNr();
        conn.sndNext = conn.initialSeqNr;
        conn.sndUnack = conn.initialSeqNr;
        conn.sndUnackTime = (int) (System.currentTimeMillis() & 0xFFFFFFFF);
        conn.rcvWindow = initialWindow;
        conn.sndWindow = packet.getWindow();
        checkAndHandleMSS(conn, packet);

        packet.emptyPayload();
        packet.setSYNFlag();

        conn.synToSend = true;
        conn.synToSendSeq = conn.sndNext + 1;

        packet.setMMS();

        skb.incrementUseCount();
        sendEmptyPacket(conn, skb, conn.getConnectionKey().remoteIP);

        conn.setState(TCPConnection.State.SYN_Rcvd);
    }

    /**
     * Method which is invoked when a segment arrives in state SYN_RECIEVED It
     * looks for the acknowledge of the previous sent SYN-ACK. If such a
     * acknowledge arrives the 3-way-handshake is finished and the state is
     * switched to ESTABLISHED. In this method also the blocking listen method
     * will be woken up if the connection was established or a error occured.
     * If some data was sent with the segment it is processed and new data
     * is sent if available.
     * The behaviour on other setted flags and theb check of Syn and Ack
     * numbers is implementet according RFC 793.
     *
     * @param conn
     *            <code>TCPConnection</code> for who the packet was sent
     * @param pay
     *            <code>Payload</code> which contains the segment
     */
    private void establishConnectionPassive2(TCPConnection conn, SocketBuffer skb)
    {
        TCPPacket packet = new TCPPacket(skb);
        IP4Packet ipPacket = new IP4Packet(skb);

        // SYN RECIEVED STATE
        if (!isSeqAcceptable(conn, skb))
            return;

        if (packet.isRSTFlagSet())
        {
            if (conn.previousState == TCPConnection.State.SYN_Sent)
            {
                System.out.println("ERROR: RST set, closing connection");
                conn.setState(TCPConnection.State.Closed);
            }
            else if (conn.previousState == TCPConnection.State.Listen)
            {
                System.out.println("ERROR: RST set, returning to state LISTEN");
                conn.setState(TCPConnection.State.Listen);
            }
            return;
        }


//		if (TCPPacket.isSYNFlagSet(pay))
//		{
//			if (Debug.enabled)
//				Debug.println("ERROR: SYN Flag set! sending back a reset", Debug.DBG_TCP);
//			sendBackReset(pay);
//			conn.abort();
//			if (conn.getPreviousState() == TCPConnection.STATE_LISTEN)
//				// Wake up listening connections
//				synchronized (conn)
//				{
//					conn.notifyAll();
//				}
//			return;
//		}
        if (!packet.isACKFlagSet())
        {
            return;
        }
        if (!isAckNrInWindow(conn, (int) packet.getAckNr()))
        {
            sendBackReset(skb);
            return;
        }

        handleAck(conn, skb);
        conn.sndWindow = packet.getWindow();
        conn.sndWndLastUpdateSeq = packet.getSeqNr();
        conn.sndWndLastUpdateAck = packet.getAckNr();

        conn.setState(TCPConnection.State.Established);

        synchronized (conn)
		{
			conn.notifyAll();
		}

        receivePayload(conn, skb);
    }

    /**
     * Method which is invoken when a segment arrives in state ESTABLISHED. After some
     * initial parameter checks on the received segment <code>receiveAndSendData()</code>
     * will do the most of the work
     *
     * @param conn
     *            <code>TCPConnection</code> for who the packet was sent
     * @param pay
     *            <code>Payload</code> which contains the segment
     */
    private void handleEstablishedState(TCPConnection conn, SocketBuffer skb)
    {
        TCPPacket packet = new TCPPacket(skb);
        IP4Packet ipPacket = new IP4Packet(skb);

        // STATE_ESTABLISHED
        if (!isSeqAcceptable(conn, skb))
            return;

        if (packet.isRSTFlagSet())
        {
            System.out.println("ERROR: RESET Flag set!, closing connection");
            // inform user
            //conn.abort();
            return;
        }

        if (packet.isSYNFlagSet())
        {
            System.out.println("ERROR: SYN Flag set! closing connection");
            // inform user
            //conn.abort();
            return;
        }

        if (!handleAck(conn, skb))
            return;

        receivePayload(conn, skb);
    }

    /**
     * Processes data for established state starting checking the urg bit (RFC,
     * pg 73) {@link #isSeqAcceptable} must be checked before!
     * Here also Segments who lie in the window but are not the next awaited
     * segment are stored for later. If now the next awaited segment is received
     * also the previously stored "future segments" are processed.
     * If the FIN flag is set in the <code>Payload</code> it will be processed
     * calling <code>processFIN()</code>
     * TODO: Send collective acks
     *
     * @param conn
     * 			<code>TCPConnection</code> for which the segment was sent.
     * @param pay
     *			<code>Payload</code> containing the data
     */

    private void receivePayload(TCPConnection conn, SocketBuffer skb) {
        TCPPacket packet = new TCPPacket(skb);
        IP4Packet ipPacket = new IP4Packet(skb);

        if (packet.isURGFlagSet()) {
            // TODO: switch to urgent mode!
        }

        // We assume that the sequence number was checked correctly before with
        // isSeqAcceptable - so the packet lies within the receiver window
        boolean sendFIN = false;

        // Store segment for later use
        long bytesWritten = 0;
        if (packet.calculateSegmentLength() > 0) {
            skb.incrementUseCount();
            bytesWritten = conn.addReceivedSegment(packet);
            System.out.println("Stored "+bytesWritten+" segment bytes");
        }
        skb = null;

        if (packet.isFINFlagSet()) {
            sendFIN = processFIN(conn);
        }

        if (!sendFIN) {
            if (bytesWritten == 0) {
                return;
            }

            if (!conn.ackDeferred) {
                System.out.println("Deferring ACK");
                conn.ackDeferred = true;
                conn.ackDeferredTime = (int) (System.currentTimeMillis() & 0xFFFFFFFF);
                return;
            }
        }

        if (skb == null) {
            if(!conn.transmitPacketList.isEmpty()) {
                TCPConnection.TransmitPacketHolder holder = conn.transmitPacketList.removeFirst();
                skb = holder.packet.skb;
                packet = holder.packet;
            } else {
                skb = SocketBuffer.getNextAvailableSocketBuffer();
                packet = new TCPPacket(skb);
                packet.emptyPayload();
            }
        }

        if (sendFIN) {
            packet.setFINFlag();
        }

        // We should only be sending an ack if there is not data to send. Otherwise, sending thread should deliver acks
        sendEmptyPacket(conn, skb, conn.getConnectionKey().remoteIP, (bytesWritten > 0 || conn.ackDeferred ? true : false));

        conn.ackDeferred = false;
    }

    /**
     * Receive a segment in STATE_FIN_WAIT_1. Method is invoked after user sent a
     * CLOSE call, and the other sends something after our FIN Packet. If data comes
     * it will be processed. If finally our FIN is acknowledged the the state will
     * be switched to STATE_FIN_WAIT_2.
     * In this state we will not send more data, just retransmissions if needed
     *
     * @param conn
     *            The connection
     * @param pay
     *            The payload
     */
    private void closeConnectionActive1(TCPConnection conn, SocketBuffer skb)
    {
        // STATE_FIN_WAIT_1
        if (!isSeqAcceptable(conn, skb))
            return;

        TCPPacket packet = new TCPPacket(skb);
        IP4Packet ipPacket = new IP4Packet(skb);

        if (packet.isRSTFlagSet())
        {
            System.out.println("ERROR: RESET Flag set!");
            // inform user
            //TCPConnection.deleteConnection(conn);
            return;
        }

        if (packet.isSYNFlagSet())
        {
            System.out.println("ERROR: SYN Flag set!");
            //TCPConnection.deleteConnection(conn);
            return;
        }

        if (!handleAck(conn, skb))
            return;

        if (conn.sndNext == conn.sndUnack && conn.oStream.isNoMoreDataToRead()) // FIN ACKed
        {
            conn.setState(TCPConnection.State.FIN_Wait_2);
        }
        receivePayload(conn, skb);
    }

    /**
     * Handles the active closing of a connection in state FIN_WAIT_2. Does just
     * the same as in ESTABLISHED. Since user called close the output stream is
     * closed, so no new data can't be sent, also retransmissions are not done because
     * the other side has just acknowledged our FIN which is (hopefully) the last sequence
     * number of the data sent by us.
     * We are just waiting for the remote FIN
     *
     * @param conn
     *            The Connection
     * @param skb
     *            The SocketBuffer
     */
    private void closeConnectionActive2(TCPConnection conn, SocketBuffer skb)
    {
        // STATE_FIN_WAIT_2
        // do the same as in ESTABLISHED
        handleEstablishedState(conn, skb);
    }

    /**
     * Method which is invoken when a segment arrives in state CLOSE_WAIT. Here
     * Data is just acknowledged but not stored! The state CLOSE_WAIT can be
     * left just with an user input
     *
     * The behaviour on setted flags and the check of Syn and Ack numbers is
     * implementet according RFC 793
     *
     * @param conn
     *            TCPConnection for who the packet was sent
     * @param pay
     *            Payload which contains the segment
     */
    private void closeConnectionPassive1(TCPConnection conn, SocketBuffer skb)
    {
        // STATE_CLOSE_WAIT
        if (!isSeqAcceptable(conn, skb))
            return;

        TCPPacket packet = new TCPPacket(skb);
        IP4Packet ipPacket = new IP4Packet(skb);

        if (packet.isRSTFlagSet())
        {
            System.out.println("ERROR: RST Flag set! sending back a reset");
            sendBackReset(skb);
            conn.abort();
            return;
        }
        if (packet.isSYNFlagSet())
        {
            System.out.println("ERROR: SYN Flag set! sending back a reset");
            sendBackReset(skb);
            conn.abort();
            return;
        }

        if (!handleAck(conn, skb))
            return;

        //send FIN if user called close()
        if (conn.flushAndClose)
        {
            packet.emptyPayload();
            sendEmptyPacket(conn, skb, 0,false);
            return;
        }

        System.out.println("Still waiting... no more data to read: ");
        // urg must be ignored as written in rfc
        // payload must also be ignored
        // fin doesnt mather
    }

    private void closeConnectionPassive2(TCPConnection conn, SocketBuffer skb)
    {
        // STATE_LAST_ACK
        if (!isSeqAcceptable(conn, skb)) {
            System.out.println("Unacceptable sequence Last_Ack");
            return;
        }

        TCPPacket packet = new TCPPacket(skb);
        IP4Packet ipPacket = new IP4Packet(skb);

        if (packet.isRSTFlagSet())
        {
            System.out.println("RESET Flag set, closing the connection");
            updateClosedConnection(conn);
            return;
        }
        if (packet.isSYNFlagSet())
        {
            System.out.println("ERROR: SYN Flag set!");
            updateClosedConnection(conn);
            return;
        }
        if (!packet.isACKFlagSet())
        {
            System.out.println("No ack flag in Last_Ack");
            return;
        }

        // Ack is the right ack => connection gets closed normally
        if (conn.sndNext == packet.getAckNr())
        {
            conn.setState(TCPConnection.State.Closed);
            updateClosedConnection(conn);
            return;
        }

        System.out.println("Bad packet in Last_Ack sndNext: "+conn.sndNext+" packet ack: "+packet.getAckNr());
        return;
    }

}
