package org.rowland.jinix.net;

import sun.misc.CharacterEncoder;

import javax.xml.stream.events.Characters;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;

public class ICMPProtocolHandler implements ProtocolHandler {
    InternetProtocolHandler ipHandler;

    ICMPProtocolHandler(InternetProtocolHandler ipHandler) {
        this.ipHandler = ipHandler;
    }

    @Override
    public void processMessage(SocketBuffer skb) {
        ICMPMessage.setupSKB(skb);
        ICMPMessage message = new ICMPMessage(skb);
        if (!message.hasValidCheckSum()) {
            System.out.println("Received ICMP with invalid checksum");
            return;
        }

        int messageType = message.getType();

        switch (messageType) {

            case ICMPEchoMessage.TYPE_ECHO:
                processEchoRequest(skb);
            case ICMPEchoMessage.TYPE_ECHO_REPLY:
                processEchoReqly(new ICMPEchoMessage(skb));
        }
    }

    void processEchoRequest(SocketBuffer skb) {
        skb.incrementUseCount();
        ICMPEchoMessage message = new ICMPEchoMessage(skb);
        message.setType(ICMPMessage.TYPE_ECHO_REPLY);
        message.setCheckSum();
        IP4Packet ip4Packet = new IP4Packet(skb);
        ipHandler.sendIPMessage(ip4Packet.getSourceAddress(), Protocol.ICMP, skb);
    }

    SocketBuffer createEchoRequest(int identifier, int sequenceNumber) {
        SocketBuffer skb = SocketBuffer.getNextAvailableSocketBuffer();
        ICMPMessage message = new ICMPMessage(skb, ByteBuffer.wrap("ECHO Message".getBytes(Charset.forName("US-ASCII"))));
        message.setType(ICMPMessage.TYPE_ECHO);
        message.setCode(0);
        message.setIdentifier(identifier);
        message.setSequenceNumber(sequenceNumber);
        message.setCheckSum();
        return skb;
    }

    void processEchoReqly(ICMPEchoMessage message) {
        int identifier = message.getIdentifier();
        InternetProtocolHandler.EchoSynchronizer echoSynchronizer =
                ipHandler.echoSynchronizerMap.get(Integer.valueOf(identifier));
        if (echoSynchronizer != null) {
            echoSynchronizer.sequenceNumber = message.getSequenceNumber();
            echoSynchronizer.latch.countDown();
        }
    }
}
