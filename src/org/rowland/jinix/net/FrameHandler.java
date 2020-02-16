package org.rowland.jinix.net;

import java.nio.ByteBuffer;

public interface FrameHandler {

    public void processFramePayload(EthernetDevice device, SocketBuffer skb);
}
