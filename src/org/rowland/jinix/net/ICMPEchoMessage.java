package org.rowland.jinix.net;

import java.nio.ByteBuffer;

public class ICMPEchoMessage extends ICMPMessage {

    ICMPEchoMessage(SocketBuffer skb) {
        super(skb);
    }

    short getIdentifier() {
        return ICMPMessage.getShort(4);
    }

    short getSequenceNumber() {
        return ICMPMessage.getShort(6);
    }
}
