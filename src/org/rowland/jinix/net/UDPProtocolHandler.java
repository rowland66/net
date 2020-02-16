package org.rowland.jinix.net;

public class UDPProtocolHandler implements ProtocolHandler {
    InternetProtocolHandler internetProtocolHandler;

    UDPProtocolHandler(InternetProtocolHandler ipHandler) {
        internetProtocolHandler = ipHandler;
    }

    @Override
    public void processMessage(SocketBuffer skb) {
        UDPPacket msg = new UDPPacket(skb);

        if (!msg.isValid()) {
            System.err.println("Received invalid UDP packet");
            return;
        }

        if (!msg.hasValidCheckSum()) {
            System.err.println("Received UDP packet with an invalid checksnm");
        }

        System.out.print(new String(msg.getPayload()));
    }
}
