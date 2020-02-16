package org.rowland.jinix.net;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

public interface ProtocolHandler {

    public enum Protocol {
        ICMP(1),
        UDP(17),
        TCP(6);

        public byte ipHeaderCode;

        Protocol(int ipHeaderCode) {
            this.ipHeaderCode = (byte) ipHeaderCode;
        }
    };

    public void processMessage(SocketBuffer skb);
}
